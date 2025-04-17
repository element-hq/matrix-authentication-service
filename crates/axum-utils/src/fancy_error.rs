// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    Extension,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::typed_header::TypedHeader;
use headers::ContentType;
use mas_templates::ErrorContext;

use crate::sentry::SentryEventID;

pub struct FancyError {
    context: ErrorContext,
}

impl FancyError {
    #[must_use]
    pub fn new(context: ErrorContext) -> Self {
        Self { context }
    }
}

impl std::fmt::Display for FancyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = self.context.code().unwrap_or("Internal error");
        match (self.context.description(), self.context.details()) {
            (Some(description), Some(details)) => {
                write!(f, "{code}: {description} ({details})")
            }
            (Some(message), None) | (None, Some(message)) => {
                write!(f, "{code}: {message}")
            }
            (None, None) => {
                write!(f, "{code}")
            }
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> From<E> for FancyError {
    fn from(err: E) -> Self {
        let context = ErrorContext::new()
            .with_description(format!("{err}"))
            .with_details(format!("{err:?}"));
        FancyError { context }
    }
}

impl IntoResponse for FancyError {
    fn into_response(self) -> Response {
        tracing::error!(message = %self.context);
        let error = format!("{}", self.context);
        let event_id = SentryEventID::for_last_event();
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            TypedHeader(ContentType::text()),
            event_id,
            Extension(self.context),
            error,
        )
            .into_response()
    }
}
