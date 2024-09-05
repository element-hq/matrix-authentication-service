// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{
    future::Future,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    task::{Context, Poll},
    time::Duration,
};

use event_listener::{Event, EventListener};
use futures_util::{stream::SelectAll, Stream, StreamExt};
use hyper::{Request, Response};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Connection,
    service::TowerToHyperService,
};
use pin_project_lite::pin_project;
use thiserror::Error;
use tokio_rustls::rustls::ServerConfig;
use tower::Service;
use tower_http::add_extension::AddExtension;
use tracing::Instrument;

use crate::{
    maybe_tls::{MaybeTlsAcceptor, MaybeTlsStream, TlsStreamInfo},
    proxy_protocol::{MaybeProxyAcceptor, ProxyAcceptError},
    rewind::Rewind,
    unix_or_tcp::{SocketAddr, UnixOrTcpConnection, UnixOrTcpListener},
    ConnectionInfo,
};

/// The timeout for the handshake to complete
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Server<S> {
    tls: Option<Arc<ServerConfig>>,
    proxy: bool,
    listener: UnixOrTcpListener,
    service: S,
}

impl<S> Server<S> {
    /// # Errors
    ///
    /// Returns an error if the listener couldn't be converted via [`TryInto`]
    pub fn try_new<L>(listener: L, service: S) -> Result<Self, L::Error>
    where
        L: TryInto<UnixOrTcpListener>,
    {
        Ok(Self {
            tls: None,
            proxy: false,
            listener: listener.try_into()?,
            service,
        })
    }

    #[must_use]
    pub fn new(listener: impl Into<UnixOrTcpListener>, service: S) -> Self {
        Self {
            tls: None,
            proxy: false,
            listener: listener.into(),
            service,
        }
    }

    #[must_use]
    pub const fn with_proxy(mut self) -> Self {
        self.proxy = true;
        self
    }

    #[must_use]
    pub fn with_tls(mut self, config: Arc<ServerConfig>) -> Self {
        self.tls = Some(config);
        self
    }

    /// Run a single server
    pub async fn run<B, SD>(self, shutdown: SD)
    where
        S: Service<Request<hyper::body::Incoming>, Response = Response<B>> + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: std::error::Error + Send + Sync + 'static,
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: std::error::Error + Send + Sync + 'static,
        SD: Stream + Unpin,
        SD::Item: std::fmt::Display,
    {
        run_servers(std::iter::once(self), shutdown).await;
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
enum AcceptError {
    #[error("failed to accept connection from the underlying socket")]
    Socket {
        #[source]
        source: std::io::Error,
    },

    #[error("failed to complete the TLS handshake")]
    TlsHandshake {
        #[source]
        source: std::io::Error,
    },

    #[error("failed to complete the proxy protocol handshake")]
    ProxyHandshake {
        #[source]
        source: ProxyAcceptError,
    },

    #[error("connection handshake timed out")]
    HandshakeTimeout {
        #[source]
        source: tokio::time::error::Elapsed,
    },
}

impl AcceptError {
    fn socket(source: std::io::Error) -> Self {
        Self::Socket { source }
    }

    fn tls_handshake(source: std::io::Error) -> Self {
        Self::TlsHandshake { source }
    }

    fn proxy_handshake(source: ProxyAcceptError) -> Self {
        Self::ProxyHandshake { source }
    }

    fn handshake_timeout(source: tokio::time::error::Elapsed) -> Self {
        Self::HandshakeTimeout { source }
    }
}

/// Accept a connection and do the proxy protocol and TLS handshake
///
/// Returns an error if the proxy protocol or TLS handshake failed.
/// Returns the connection, which should be used to spawn a task to serve the
/// connection.
#[allow(clippy::type_complexity)]
#[tracing::instrument(
    name = "accept",
    skip_all,
    fields(
        network.protocol.name = "http",
        network.peer.address,
        network.peer.port,
    ),
    err,
)]
async fn accept<S, B>(
    maybe_proxy_acceptor: &MaybeProxyAcceptor,
    maybe_tls_acceptor: &MaybeTlsAcceptor,
    peer_addr: SocketAddr,
    stream: UnixOrTcpConnection,
    service: S,
) -> Result<
    Connection<
        'static,
        TokioIo<MaybeTlsStream<Rewind<UnixOrTcpConnection>>>,
        TowerToHyperService<AddExtension<S, ConnectionInfo>>,
        TokioExecutor,
    >,
    AcceptError,
>
where
    S: Service<Request<hyper::body::Incoming>, Response = Response<B>> + Send + Clone + 'static,
    S::Error: std::error::Error + Send + Sync + 'static,
    S::Future: Send + 'static,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let span = tracing::Span::current();

    match peer_addr {
        SocketAddr::Net(addr) => {
            span.record("network.peer.address", tracing::field::display(addr.ip()));
            span.record("network.peer.port", addr.port());
        }
        SocketAddr::Unix(ref addr) => {
            span.record("network.peer.address", tracing::field::debug(addr));
        }
    }

    // Wrap the connection acceptation logic in a timeout
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        let (proxy, stream) = maybe_proxy_acceptor
            .accept(stream)
            .await
            .map_err(AcceptError::proxy_handshake)?;

        let stream = maybe_tls_acceptor
            .accept(stream)
            .await
            .map_err(AcceptError::tls_handshake)?;

        let tls = stream.tls_info();

        // Figure out if it's HTTP/2 based on the negociated ALPN info
        let is_h2 = tls.as_ref().map_or(false, TlsStreamInfo::is_alpn_h2);

        let info = ConnectionInfo {
            tls,
            proxy,
            net_peer_addr: peer_addr.into_net(),
        };

        let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        if is_h2 {
            builder = builder.http2_only();
        }
        builder.http1().keep_alive(true);

        let service = TowerToHyperService::new(AddExtension::new(service, info));

        let conn = builder
            .serve_connection(TokioIo::new(stream), service)
            .into_owned();

        Ok(conn)
    })
    .instrument(span)
    .await
    .map_err(AcceptError::handshake_timeout)?
}

pin_project! {
    /// A wrapper around a connection that can be aborted when a shutdown signal is received.
    ///
    /// This works by sharing an atomic boolean between all connections, and when a shutdown
    /// signal is received, the boolean is set to true. The connection will then check the
    /// boolean before polling the underlying connection, and if it's true, it will start a
    /// graceful shutdown.
    ///
    /// We also use an event listener to wake up the connection when the shutdown signal is
    /// received, because the connection needs to be polled again to start the graceful shutdown.
    struct AbortableConnection<C> {
        #[pin]
        connection: C,
        #[pin]
        shutdown_listener: EventListener,
        shutdown_in_progress: Arc<AtomicBool>,
        did_start_shutdown: bool,
    }
}

impl<C> AbortableConnection<C> {
    fn new(connection: C, shutdown_in_progress: &Arc<AtomicBool>, event: &Arc<Event>) -> Self {
        Self {
            connection,
            shutdown_listener: event.listen(),
            shutdown_in_progress: Arc::clone(shutdown_in_progress),
            did_start_shutdown: false,
        }
    }
}

impl<T, S, B> Future
    for AbortableConnection<Connection<'static, T, TowerToHyperService<S>, TokioExecutor>>
where
    Connection<'static, T, TowerToHyperService<S>, TokioExecutor>: Future,
    S: Service<Request<hyper::body::Incoming>, Response = Response<B>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: std::error::Error + Send + Sync,
    T: hyper::rt::Read + hyper::rt::Write + Unpin,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Output = <Connection<'static, T, TowerToHyperService<S>, TokioExecutor> as Future>::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        // Poll the shutdown signal, so that wakers get registered.
        // XXX: I don't think we care about the result of this poll, since it's only
        // really to register wakers. But I'm not sure if it's safe to
        // ignore the result.
        let _ = this.shutdown_listener.poll(cx);

        if !*this.did_start_shutdown
            && this
                .shutdown_in_progress
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            *this.did_start_shutdown = true;
            this.connection.as_mut().graceful_shutdown();
        }

        this.connection.poll(cx)
    }
}

#[allow(clippy::too_many_lines)]
pub async fn run_servers<S, B, SD>(listeners: impl IntoIterator<Item = Server<S>>, mut shutdown: SD)
where
    S: Service<Request<hyper::body::Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::error::Error + Send + Sync + 'static,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
    SD: Stream + Unpin,
    SD::Item: std::fmt::Display,
{
    // Create a stream of accepted connections out of the listeners
    let mut accept_stream: SelectAll<_> = listeners
        .into_iter()
        .map(|server| {
            let maybe_proxy_acceptor = MaybeProxyAcceptor::new(server.proxy);
            let maybe_tls_acceptor = MaybeTlsAcceptor::new(server.tls);
            futures_util::stream::poll_fn(move |cx| {
                let res =
                    std::task::ready!(server.listener.poll_accept(cx)).map(|(addr, stream)| {
                        (
                            maybe_proxy_acceptor,
                            maybe_tls_acceptor.clone(),
                            server.service.clone(),
                            addr,
                            stream,
                        )
                    });
                Poll::Ready(Some(res))
            })
        })
        .collect();

    // A JoinSet which collects connections that are being accepted
    let mut accept_tasks = tokio::task::JoinSet::new();
    // A JoinSet which collects connections that are being served
    let mut connection_tasks = tokio::task::JoinSet::new();

    // A shared atomic boolean to tell all connections to shutdown
    let shutdown_in_progress = Arc::new(AtomicBool::new(false));
    let shutdown_event = Arc::new(Event::new());

    loop {
        tokio::select! {
            biased;

            // First look for the shutdown signal
            res = shutdown.next() => {
                let why = res.map_or_else(|| String::from("???"), |why| format!("{why}"));
                tracing::info!("Received shutdown signal ({why})");

                break;
            },

            // Poll on the JoinSet to collect connections to serve
            res = accept_tasks.join_next(), if !accept_tasks.is_empty() => {
                match res {
                    Some(Ok(Ok(connection))) => {
                        tracing::trace!("Accepted connection");
                        let conn = AbortableConnection::new(connection, &shutdown_in_progress, &shutdown_event);
                        connection_tasks.spawn(conn);
                    },
                    Some(Ok(Err(_e))) => { /* Connection did not finish handshake, error should be logged in `accept` */ },
                    Some(Err(e)) => tracing::error!("Join error: {e}"),
                    None => tracing::error!("Join set was polled even though it was empty"),
                }
            },

            // Poll on the JoinSet to collect finished connections
            res = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                match res {
                    Some(Ok(Ok(()))) => tracing::trace!("Connection finished"),
                    Some(Ok(Err(e))) => tracing::error!("Error while serving connection: {e}"),
                    Some(Err(e)) => tracing::error!("Join error: {e}"),
                    None => tracing::error!("Join set was polled even though it was empty"),
                }
            },

            // Look for connections to accept
            res = accept_stream.next(), if !accept_stream.is_empty() => {
                // SAFETY: We shouldn't reach this branch if the stream set is empty
                let Some(res) = res else { unreachable!() };

                // Spawn the connection in the set, so we don't have to wait for the handshake to
                // accept the next connection. This allows us to keep track of active connections
                // and waiting on them for a graceful shutdown
                accept_tasks.spawn(async move {
                    let (maybe_proxy_acceptor, maybe_tls_acceptor, service, peer_addr, stream) = res
                        .map_err(AcceptError::socket)?;
                    accept(&maybe_proxy_acceptor, &maybe_tls_acceptor, peer_addr, stream, service).await
                });
            },
        };
    }

    // Tell the active connections to shutdown
    shutdown_in_progress.store(true, std::sync::atomic::Ordering::Relaxed);
    shutdown_event.notify(usize::MAX);

    // Wait for connections to cleanup
    if !accept_tasks.is_empty() || !connection_tasks.is_empty() {
        tracing::info!(
            "There are {active} active connections ({pending} pending), performing a graceful shutdown. Send the shutdown signal again to force.",
            active = connection_tasks.len(),
            pending = accept_tasks.len(),
        );

        while !accept_tasks.is_empty() || !connection_tasks.is_empty() {
            tokio::select! {
                biased;

                // Poll on the JoinSet to collect connections to serve
                res = accept_tasks.join_next(), if !accept_tasks.is_empty() => {
                    match res {
                        Some(Ok(Ok(connection))) => {
                            tracing::trace!("Accepted connection");
                            let conn = AbortableConnection::new(connection, &shutdown_in_progress, &shutdown_event);
                            connection_tasks.spawn(conn);
                        }
                        Some(Ok(Err(_e))) => { /* Connection did not finish handshake, error should be logged in `accept` */ },
                        Some(Err(e)) => tracing::error!("Join error: {e}"),
                        None => tracing::error!("Join set was polled even though it was empty"),
                    }
                },

                // Poll on the JoinSet to collect finished connections
                res = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                    match res {
                        Some(Ok(Ok(()))) => tracing::trace!("Connection finished"),
                        Some(Ok(Err(e))) => tracing::error!("Error while serving connection: {e}"),
                        Some(Err(e)) => tracing::error!("Join error: {e}"),
                        None => tracing::error!("Join set was polled even though it was empty"),
                    }
                },

                // Handle when we receive the shutdown signal again
                res = shutdown.next() => {
                    let why = res.map_or_else(|| String::from("???"), |why| format!("{why}"));
                    tracing::warn!(
                        "Received shutdown signal again ({why}), forcing shutdown ({active} active connections, {pending} pending connections)",
                        active = connection_tasks.len(),
                        pending = accept_tasks.len(),
                    );
                    break;
                },
            }
        }
    }

    accept_tasks.shutdown().await;
    connection_tasks.shutdown().await;
    tracing::info!("Shutdown complete");
}
