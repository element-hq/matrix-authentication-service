// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::response::{IntoResponse, Response};

use crate::InternalError;

/// A simple wrapper around an error that implements [`IntoResponse`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ErrorWrapper<T>(#[from] pub T);

impl<T> IntoResponse for ErrorWrapper<T>
where
    T: std::error::Error + 'static,
{
    fn into_response(self) -> Response {
        InternalError::from(self.0).into_response()
    }
}
