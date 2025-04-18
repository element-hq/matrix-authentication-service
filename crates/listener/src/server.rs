// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures_util::{StreamExt, stream::SelectAll};
use hyper::{Request, Response};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Connection,
    service::TowerToHyperService,
};
use mas_context::LogContext;
use pin_project_lite::pin_project;
use thiserror::Error;
use tokio_rustls::rustls::ServerConfig;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use tower::Service;
use tower_http::add_extension::AddExtension;
use tracing::Instrument;

use crate::{
    ConnectionInfo,
    maybe_tls::{MaybeTlsAcceptor, MaybeTlsStream, TlsStreamInfo},
    proxy_protocol::{MaybeProxyAcceptor, ProxyAcceptError},
    rewind::Rewind,
    unix_or_tcp::{SocketAddr, UnixOrTcpConnection, UnixOrTcpListener},
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
    pub async fn run<B>(
        self,
        soft_shutdown_token: CancellationToken,
        hard_shutdown_token: CancellationToken,
    ) where
        S: Service<Request<hyper::body::Incoming>, Response = Response<B>> + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: std::error::Error + Send + Sync + 'static,
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        run_servers(
            std::iter::once(self),
            soft_shutdown_token,
            hard_shutdown_token,
        )
        .await;
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
enum AcceptError {
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
        let is_h2 = tls.as_ref().is_some_and(TlsStreamInfo::is_alpn_h2);

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
        cancellation_future: WaitForCancellationFutureOwned,
        did_start_shutdown: bool,
    }
}

impl<C> AbortableConnection<C> {
    fn new(connection: C, cancellation_token: CancellationToken) -> Self {
        Self {
            connection,
            cancellation_future: cancellation_token.cancelled_owned(),
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

        if let Poll::Ready(()) = this.cancellation_future.poll(cx) {
            if !*this.did_start_shutdown {
                *this.did_start_shutdown = true;
                this.connection.as_mut().graceful_shutdown();
            }
        }

        this.connection.poll(cx)
    }
}

#[allow(clippy::too_many_lines)]
pub async fn run_servers<S, B>(
    listeners: impl IntoIterator<Item = Server<S>>,
    soft_shutdown_token: CancellationToken,
    hard_shutdown_token: CancellationToken,
) where
    S: Service<Request<hyper::body::Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::error::Error + Send + Sync + 'static,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // This guard on the shutdown token is to ensure that if this task crashes for
    // any reason, the server will shut down
    let _guard = soft_shutdown_token.clone().drop_guard();

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

    loop {
        tokio::select! {
            biased;

            // First look for the shutdown signal
            () = soft_shutdown_token.cancelled() => {
                tracing::debug!("Shutting down listeners");
                break;
            },

            // Poll on the JoinSet to collect connections to serve
            res = accept_tasks.join_next(), if !accept_tasks.is_empty() => {
                match res {
                    Some(Ok(Some(connection))) => {
                        let token = soft_shutdown_token.child_token();
                        connection_tasks.spawn(LogContext::new("http-serve").run(async move || {
                            tracing::debug!("Accepted connection");
                            if let Err(e) = AbortableConnection::new(connection, token).await {
                                tracing::warn!(error = &*e as &dyn std::error::Error, "Failed to serve connection");
                            }
                        }));
                    },
                    Some(Ok(None)) => { /* Connection did not finish handshake, error should be logged in `accept` */ },
                    Some(Err(e)) => tracing::error!(error = &e as &dyn std::error::Error, "Join error"),
                    None => tracing::error!("Join set was polled even though it was empty"),
                }
            },

            // Poll on the JoinSet to collect finished connections
            res = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                match res {
                    Some(Ok(())) => { /* Connection finished, any errors should be logged in in the spawned task */ },
                    Some(Err(e)) => tracing::error!(error = &e as &dyn std::error::Error, "Join error"),
                    None => tracing::error!("Join set was polled even though it was empty"),
                }
            },

            // Look for connections to accept
            res = accept_stream.next() => {
                let Some(res) = res else { continue };

                // Spawn the connection in the set, so we don't have to wait for the handshake to
                // accept the next connection. This allows us to keep track of active connections
                // and waiting on them for a graceful shutdown
                accept_tasks.spawn(LogContext::new("http-accept").run(async move || {
                    let (maybe_proxy_acceptor, maybe_tls_acceptor, service, peer_addr, stream) = match res {
                        Ok(res) => res,
                        Err(e) => {
                            tracing::warn!(error = &e as &dyn std::error::Error, "Failed to accept connection from the underlying socket");
                            return None;
                        }
                    };

                    match accept(&maybe_proxy_acceptor, &maybe_tls_acceptor, peer_addr, stream, service).await {
                        Ok(connection) => Some(connection),
                        Err(e) => {
                            tracing::warn!(error = &e as &dyn std::error::Error, "Failed to accept connection");
                            None
                        }
                    }
                }));
            },
        };
    }

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
                        Some(Ok(Some(connection))) => {
                            let token = soft_shutdown_token.child_token();
                            connection_tasks.spawn(LogContext::new("http-serve").run(async || {
                                tracing::debug!("Accepted connection");
                                if let Err(e) = AbortableConnection::new(connection, token).await {
                                    tracing::warn!(error = &*e as &dyn std::error::Error, "Failed to serve connection");
                                }
                            }));
                        }
                        Some(Ok(None)) => { /* Connection did not finish handshake, error should be logged in `accept` */ },
                        Some(Err(e)) => tracing::error!(error = &e as &dyn std::error::Error, "Join error"),
                        None => tracing::error!("Join set was polled even though it was empty"),
                    }
                },

                // Poll on the JoinSet to collect finished connections
                res = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                    match res {
                        Some(Ok(())) => { /* Connection finished, any errors should be logged in in the spawned task */ },
                        Some(Err(e)) => tracing::error!(error = &e as &dyn std::error::Error, "Join error"),
                        None => tracing::error!("Join set was polled even though it was empty"),
                    }
                },

                // Handle when we are asked to hard shutdown
                () = hard_shutdown_token.cancelled() => {
                    tracing::warn!(
                        "Forcing shutdown ({active} active connections, {pending} pending connections)",
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
}
