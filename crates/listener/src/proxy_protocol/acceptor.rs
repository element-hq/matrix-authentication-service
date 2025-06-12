// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use bytes::BytesMut;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::ProxyProtocolV1Info;
use crate::rewind::Rewind;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProxyAcceptor {
    _private: (),
}

#[derive(Debug, Error)]
#[error(transparent)]
pub enum ProxyAcceptError {
    Parse(#[from] super::v1::ParseError),
    Read(#[from] std::io::Error),
}

impl ProxyAcceptor {
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Accept a proxy-protocol stream
    ///
    /// # Errors
    ///
    /// Returns an error on read error on the underlying stream, or when the
    /// proxy protocol preamble couldn't be parsed
    pub async fn accept<T>(
        &self,
        mut stream: T,
    ) -> Result<(ProxyProtocolV1Info, Rewind<T>), ProxyAcceptError>
    where
        T: AsyncRead + Unpin,
    {
        let mut buf = BytesMut::new();
        let info = loop {
            stream.read_buf(&mut buf).await?;

            match ProxyProtocolV1Info::parse(&mut buf) {
                Ok(info) => break info,
                Err(e) if e.not_enough_bytes() => {}
                Err(e) => return Err(e.into()),
            }
        };

        let stream = Rewind::new_buffered(stream, buf.into());

        Ok((info, stream))
    }
}
