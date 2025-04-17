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

impl SentryEventID {
    /// Create a new Sentry event ID header for the last event on the hub.
    pub fn for_last_event() -> Option<Self> {
        sentry::last_event_id().map(Self)
    }
}

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

/// Record an error. It will emit a tracing event with the error level if
/// matches the pattern, warning otherwise. It also returns the Sentry event ID
/// if the error was recorded.
#[macro_export]
macro_rules! record_error {
    ($error:expr, !) => {{
        tracing::warn!(message = &$error as &dyn std::error::Error);
        Option::<$crate::sentry::SentryEventID>::None
    }};

    ($error:expr, $pattern:pat) => {
        if let $pattern = $error {
            tracing::error!(message = &$error as &dyn std::error::Error);

            // With the `sentry-tracing` integration, Sentry should have
            // captured an error, so let's extract the last event ID from the
            // current hub
            $crate::sentry::SentryEventID::for_last_event()
        } else {
            tracing::warn!(message = &$error as &dyn std::error::Error);
            None
        }
    };
}
