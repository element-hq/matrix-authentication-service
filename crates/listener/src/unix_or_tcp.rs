// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! A listener which can listen on either TCP sockets or on UNIX domain sockets

// TODO: Unlink the UNIX socket on drop?

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
};

pub enum SocketAddr {
    Unix(tokio::net::unix::SocketAddr),
    Net(std::net::SocketAddr),
}

impl From<tokio::net::unix::SocketAddr> for SocketAddr {
    fn from(value: tokio::net::unix::SocketAddr) -> Self {
        Self::Unix(value)
    }
}

impl From<std::net::SocketAddr> for SocketAddr {
    fn from(value: std::net::SocketAddr) -> Self {
        Self::Net(value)
    }
}

impl std::fmt::Debug for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix(l) => std::fmt::Debug::fmt(l, f),
            Self::Net(l) => std::fmt::Debug::fmt(l, f),
        }
    }
}

impl SocketAddr {
    #[must_use]
    pub fn into_net(self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Net(socket) => Some(socket),
            Self::Unix(_) => None,
        }
    }

    #[must_use]
    pub fn into_unix(self) -> Option<tokio::net::unix::SocketAddr> {
        match self {
            Self::Net(_) => None,
            Self::Unix(socket) => Some(socket),
        }
    }

    #[must_use]
    pub const fn as_net(&self) -> Option<&std::net::SocketAddr> {
        match self {
            Self::Net(socket) => Some(socket),
            Self::Unix(_) => None,
        }
    }

    #[must_use]
    pub const fn as_unix(&self) -> Option<&tokio::net::unix::SocketAddr> {
        match self {
            Self::Net(_) => None,
            Self::Unix(socket) => Some(socket),
        }
    }
}

pub enum UnixOrTcpListener {
    Unix(UnixListener),
    Tcp(TcpListener),
}

impl From<UnixListener> for UnixOrTcpListener {
    fn from(listener: UnixListener) -> Self {
        Self::Unix(listener)
    }
}

impl From<TcpListener> for UnixOrTcpListener {
    fn from(listener: TcpListener) -> Self {
        Self::Tcp(listener)
    }
}

impl TryFrom<std::os::unix::net::UnixListener> for UnixOrTcpListener {
    type Error = std::io::Error;

    fn try_from(listener: std::os::unix::net::UnixListener) -> Result<Self, Self::Error> {
        listener.set_nonblocking(true)?;
        Ok(Self::Unix(UnixListener::from_std(listener)?))
    }
}

impl TryFrom<std::net::TcpListener> for UnixOrTcpListener {
    type Error = std::io::Error;

    fn try_from(listener: std::net::TcpListener) -> Result<Self, Self::Error> {
        listener.set_nonblocking(true)?;
        Ok(Self::Tcp(TcpListener::from_std(listener)?))
    }
}

impl UnixOrTcpListener {
    /// Get the local address of the listener
    ///
    /// # Errors
    ///
    /// Returns an error on rare cases where the underlying [`TcpListener`] or
    /// [`UnixListener`] couldn't provide the local address
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            Self::Unix(listener) => listener.local_addr().map(SocketAddr::from),
            Self::Tcp(listener) => listener.local_addr().map(SocketAddr::from),
        }
    }

    pub const fn is_unix(&self) -> bool {
        matches!(self, Self::Unix(_))
    }

    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    /// Accept an incoming connection
    ///
    /// # Cancel safety
    ///
    /// This function is safe to cancel, as both [`UnixListener::accept`] and
    /// [`TcpListener::accept`] are safe to cancel.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket couldn't accept the connection
    pub async fn accept(&self) -> Result<(SocketAddr, UnixOrTcpConnection), std::io::Error> {
        match self {
            Self::Unix(listener) => {
                let (stream, remote_addr) = listener.accept().await?;

                let socket = socket2::SockRef::from(&stream);
                socket.set_keepalive(true)?;
                socket.set_nodelay(true)?;

                Ok((remote_addr.into(), UnixOrTcpConnection::Unix { stream }))
            }
            Self::Tcp(listener) => {
                let (stream, remote_addr) = listener.accept().await?;

                let socket = socket2::SockRef::from(&stream);
                socket.set_keepalive(true)?;
                socket.set_nodelay(true)?;

                Ok((remote_addr.into(), UnixOrTcpConnection::Tcp { stream }))
            }
        }
    }

    /// Poll for an incoming connection
    ///
    /// # Cancel safety
    ///
    /// This function is safe to cancel, as both [`UnixListener::poll_accept`]
    /// and [`TcpListener::poll_accept`] are safe to cancel.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket couldn't accept the connection
    pub fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(SocketAddr, UnixOrTcpConnection), std::io::Error>> {
        match self {
            Self::Unix(listener) => {
                let (stream, remote_addr) = ready!(listener.poll_accept(cx)?);

                let socket = socket2::SockRef::from(&stream);
                socket.set_keepalive(true)?;
                socket.set_nodelay(true)?;

                Poll::Ready(Ok((
                    remote_addr.into(),
                    UnixOrTcpConnection::Unix { stream },
                )))
            }
            Self::Tcp(listener) => {
                let (stream, remote_addr) = ready!(listener.poll_accept(cx)?);

                let socket = socket2::SockRef::from(&stream);
                socket.set_keepalive(true)?;
                socket.set_nodelay(true)?;

                Poll::Ready(Ok((
                    remote_addr.into(),
                    UnixOrTcpConnection::Tcp { stream },
                )))
            }
        }
    }
}

pin_project_lite::pin_project! {
    #[project = UnixOrTcpConnectionProj]
    pub enum UnixOrTcpConnection {
        Unix {
            #[pin]
            stream: UnixStream,
        },

        Tcp {
            #[pin]
            stream: TcpStream,
        },
    }
}

impl From<TcpStream> for UnixOrTcpConnection {
    fn from(stream: TcpStream) -> Self {
        Self::Tcp { stream }
    }
}

impl UnixOrTcpConnection {
    /// Get the local address of the stream
    ///
    /// # Errors
    ///
    /// Returns an error on rare cases where the underlying [`TcpStream`] or
    /// [`UnixStream`] couldn't provide the local address
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            Self::Unix { stream } => stream.local_addr().map(SocketAddr::from),
            Self::Tcp { stream } => stream.local_addr().map(SocketAddr::from),
        }
    }

    /// Get the remote address of the stream
    ///
    /// # Errors
    ///
    /// Returns an error on rare cases where the underlying [`TcpStream`] or
    /// [`UnixStream`] couldn't provide the remote address
    pub fn peer_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            Self::Unix { stream } => stream.peer_addr().map(SocketAddr::from),
            Self::Tcp { stream } => stream.peer_addr().map(SocketAddr::from),
        }
    }
}

impl AsyncRead for UnixOrTcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project() {
            UnixOrTcpConnectionProj::Unix { stream } => stream.poll_read(cx, buf),
            UnixOrTcpConnectionProj::Tcp { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UnixOrTcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project() {
            UnixOrTcpConnectionProj::Unix { stream } => stream.poll_write(cx, buf),
            UnixOrTcpConnectionProj::Tcp { stream } => stream.poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.project() {
            UnixOrTcpConnectionProj::Unix { stream } => stream.poll_write_vectored(cx, bufs),
            UnixOrTcpConnectionProj::Tcp { stream } => stream.poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            UnixOrTcpConnection::Unix { stream } => stream.is_write_vectored(),
            UnixOrTcpConnection::Tcp { stream } => stream.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.project() {
            UnixOrTcpConnectionProj::Unix { stream } => stream.poll_flush(cx),
            UnixOrTcpConnectionProj::Tcp { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project() {
            UnixOrTcpConnectionProj::Unix { stream } => stream.poll_shutdown(cx),
            UnixOrTcpConnectionProj::Tcp { stream } => stream.poll_shutdown(cx),
        }
    }
}
