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

fn build_context(mut err: &dyn std::error::Error) -> ErrorContext {
    let description = err.to_string();
    let mut details = Vec::new();
    while let Some(source) = err.source() {
        err = source;
        details.push(err.to_string());
    }

    ErrorContext::new()
        .with_description(description)
        .with_details(details.join("\n"))
}

pub struct GenericError {
    error: Box<dyn std::error::Error + 'static>,
    code: StatusCode,
}

impl IntoResponse for GenericError {
    fn into_response(self) -> Response {
        tracing::warn!(message = &*self.error);
        let context = build_context(&*self.error);
        let context_text = format!("{context}");

        (
            self.code,
            TypedHeader(ContentType::text()),
            Extension(context),
            context_text,
        )
            .into_response()
    }
}

impl GenericError {
    pub fn new(code: StatusCode, err: impl std::error::Error + 'static) -> Self {
        Self {
            error: Box::new(err),
            code,
        }
    }
}

pub struct InternalError {
    error: Box<dyn std::error::Error + 'static>,
}

impl IntoResponse for InternalError {
    fn into_response(self) -> Response {
        tracing::error!(message = &*self.error);
        let event_id = SentryEventID::for_last_event();
        let context = build_context(&*self.error);
        let context_text = format!("{context}");

        (
            StatusCode::INTERNAL_SERVER_ERROR,
            TypedHeader(ContentType::text()),
            event_id,
            Extension(context),
            context_text,
        )
            .into_response()
    }
}

impl<E: std::error::Error + 'static> From<E> for InternalError {
    fn from(err: E) -> Self {
        Self {
            error: Box::new(err),
        }
    }
}

impl InternalError {
    /// Create a new error from a boxed error
    #[must_use]
    pub fn new(error: Box<dyn std::error::Error + 'static>) -> Self {
        Self { error }
    }

    /// Create a new error from an [`anyhow::Error`]
    #[must_use]
    pub fn from_anyhow(err: anyhow::Error) -> Self {
        Self {
            error: err.into_boxed_dyn_error(),
        }
    }
}
