// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![deny(rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]

//! An utility crate to build flexible [`hyper`] listeners, with optional TLS
//! and proxy protocol support.

use self::{maybe_tls::TlsStreamInfo, proxy_protocol::ProxyProtocolV1Info};

pub mod maybe_tls;
pub mod proxy_protocol;
pub mod rewind;
pub mod server;
pub mod unix_or_tcp;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    tls: Option<TlsStreamInfo>,
    proxy: Option<ProxyProtocolV1Info>,
    net_peer_addr: Option<std::net::SocketAddr>,
}

impl ConnectionInfo {
    /// Returns informations about the TLS connection. Returns [`None`] if the
    /// connection was not TLS.
    #[must_use]
    pub fn get_tls_ref(&self) -> Option<&TlsStreamInfo> {
        self.tls.as_ref()
    }

    /// Returns informations about the proxy protocol connection. Returns
    /// [`None`] if the connection was not using the proxy protocol.
    #[must_use]
    pub fn get_proxy_ref(&self) -> Option<&ProxyProtocolV1Info> {
        self.proxy.as_ref()
    }

    /// Returns the remote peer address. Returns [`None`] if the connection was
    /// established via a UNIX domain socket.
    #[must_use]
    pub fn get_peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.net_peer_addr
    }
}
