// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::convert::Infallible;

use axum::response::{IntoResponseParts, ResponseParts};
use sentry::types::Uuid;

/// A wrapper to include a Sentry event ID in the response headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SentryEventID(Uuid);

impl From<Uuid> for SentryEventID {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl IntoResponseParts for SentryEventID {
    type Error = Infallible;
    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        res.headers_mut()
            .insert("X-Sentry-Event-ID", self.0.to_string().parse().unwrap());

        Ok(res)
    }
}
