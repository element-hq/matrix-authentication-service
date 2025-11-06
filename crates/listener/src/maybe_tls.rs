// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ProtocolVersion, ServerConfig, ServerConnection, SupportedCipherSuite,
        pki_types::CertificateDer,
    },
};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TlsStreamInfo {
    pub protocol_version: ProtocolVersion,
    pub negotiated_cipher_suite: SupportedCipherSuite,
    pub sni_hostname: Option<String>,
    pub alpn_protocol: Option<Vec<u8>>,
    pub peer_certificates: Option<Vec<CertificateDer<'static>>>,
}

impl TlsStreamInfo {
    #[must_use]
    pub fn is_alpn_h2(&self) -> bool {
        matches!(self.alpn_protocol.as_deref(), Some(b"h2"))
    }
}

pin_project_lite::pin_project! {
    #[project = MaybeTlsStreamProj]
    pub enum MaybeTlsStream<T> {
        Secure {
            #[pin]
            stream: tokio_rustls::server::TlsStream<T>
        },
        Insecure {
            #[pin]
            stream: T,
        },
    }
}

impl<T> MaybeTlsStream<T> {
    /// Get a reference to the underlying IO stream
    ///
    /// Returns [`None`] if the stream closed before the TLS handshake finished.
    /// It is guaranteed to return [`Some`] value after the handshake finished,
    /// or if it is a non-TLS connection.
    pub fn get_ref(&self) -> &T {
        match self {
            Self::Secure { stream } => stream.get_ref().0,
            Self::Insecure { stream } => stream,
        }
    }

    /// Get a ref to the [`ServerConnection`] of the establish TLS stream.
    ///
    /// Returns [`None`] for non-TLS connections.
    pub fn get_tls_connection(&self) -> Option<&ServerConnection> {
        match self {
            Self::Secure { stream } => Some(stream.get_ref().1),
            Self::Insecure { .. } => None,
        }
    }

    /// Gather informations about the TLS connection. Returns `None` if the
    /// stream is not a TLS stream.
    ///
    /// # Panics
    ///
    /// Panics if the TLS handshake is not done yet, which should never happen
    pub fn tls_info(&self) -> Option<TlsStreamInfo> {
        let conn = self.get_tls_connection()?;

        // SAFETY: we're getting the protocol version and cipher suite *after* the
        // handshake, so this should never lead to a panic
        let protocol_version = conn
            .protocol_version()
            .expect("TLS handshake is not done yet");
        let negotiated_cipher_suite = conn
            .negotiated_cipher_suite()
            .expect("TLS handshake is not done yet");

        let sni_hostname = conn.server_name().map(ToOwned::to_owned);
        let alpn_protocol = conn.alpn_protocol().map(ToOwned::to_owned);
        let peer_certificates = conn.peer_certificates().map(|certs| {
            certs
                .iter()
                .cloned()
                .map(CertificateDer::into_owned)
                .collect()
        });
        Some(TlsStreamInfo {
            protocol_version,
            negotiated_cipher_suite,
            sni_hostname,
            alpn_protocol,
            peer_certificates,
        })
    }
}

impl<T> AsyncRead for MaybeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        match self.project() {
            MaybeTlsStreamProj::Secure { stream } => stream.poll_read(cx, buf),
            MaybeTlsStreamProj::Insecure { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for MaybeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.project() {
            MaybeTlsStreamProj::Secure { stream } => stream.poll_write(cx, buf),
            MaybeTlsStreamProj::Insecure { stream } => stream.poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project() {
            MaybeTlsStreamProj::Secure { stream } => stream.poll_write_vectored(cx, bufs),
            MaybeTlsStreamProj::Insecure { stream } => stream.poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Secure { stream } => stream.is_write_vectored(),
            Self::Insecure { stream } => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            MaybeTlsStreamProj::Secure { stream } => stream.poll_flush(cx),
            MaybeTlsStreamProj::Insecure { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            MaybeTlsStreamProj::Secure { stream } => stream.poll_shutdown(cx),
            MaybeTlsStreamProj::Insecure { stream } => stream.poll_shutdown(cx),
        }
    }
}

#[derive(Clone)]
pub struct MaybeTlsAcceptor {
    tls_config: Option<Arc<ServerConfig>>,
}

impl MaybeTlsAcceptor {
    #[must_use]
    pub fn new(tls_config: Option<Arc<ServerConfig>>) -> Self {
        Self { tls_config }
    }

    #[must_use]
    pub fn new_secure(tls_config: Arc<ServerConfig>) -> Self {
        Self {
            tls_config: Some(tls_config),
        }
    }

    #[must_use]
    pub fn new_insecure() -> Self {
        Self { tls_config: None }
    }

    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.tls_config.is_some()
    }

    /// Accept a connection and do the TLS handshake
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS handshake failed
    pub async fn accept<T>(&self, stream: T) -> Result<MaybeTlsStream<T>, std::io::Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        match &self.tls_config {
            Some(config) => {
                let acceptor = TlsAcceptor::from(config.clone());
                let stream = acceptor.accept(stream).await?;
                Ok(MaybeTlsStream::Secure { stream })
            }
            None => Ok(MaybeTlsStream::Insecure { stream }),
        }
    }
}
