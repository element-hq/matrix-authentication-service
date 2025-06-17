// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use tokio::io::AsyncRead;

use super::{ProxyAcceptor, ProxyProtocolV1Info, acceptor::ProxyAcceptError};
use crate::rewind::Rewind;

#[derive(Clone, Copy)]
pub struct MaybeProxyAcceptor {
    acceptor: Option<ProxyAcceptor>,
}

impl MaybeProxyAcceptor {
    #[must_use]
    pub const fn new(proxied: bool) -> Self {
        let acceptor = if proxied {
            Some(ProxyAcceptor::new())
        } else {
            None
        };

        Self { acceptor }
    }

    #[must_use]
    pub const fn new_proxied(acceptor: ProxyAcceptor) -> Self {
        Self {
            acceptor: Some(acceptor),
        }
    }

    #[must_use]
    pub const fn new_unproxied() -> Self {
        Self { acceptor: None }
    }

    #[must_use]
    pub const fn is_proxied(&self) -> bool {
        self.acceptor.is_some()
    }

    /// Accept a connection and do the proxy protocol handshake
    ///
    /// # Errors
    ///
    /// Returns an error if the proxy protocol handshake failed
    pub async fn accept<T>(
        &self,
        stream: T,
    ) -> Result<(Option<ProxyProtocolV1Info>, Rewind<T>), ProxyAcceptError>
    where
        T: AsyncRead + Unpin,
    {
        if let Some(acceptor) = self.acceptor {
            let (info, stream) = acceptor.accept(stream).await?;
            Ok((Some(info), stream))
        } else {
            let stream = Rewind::new(stream);
            Ok((None, stream))
        }
    }
}
