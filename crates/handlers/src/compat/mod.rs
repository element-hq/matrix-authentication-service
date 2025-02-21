// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use serde::Serialize;

pub(crate) mod login;
pub(crate) mod login_sso_complete;
pub(crate) mod login_sso_redirect;
pub(crate) mod logout;
pub(crate) mod refresh;

#[derive(Debug, Serialize)]
struct MatrixError {
    errcode: &'static str,
    error: &'static str,
    #[serde(skip)]
    status: StatusCode,
}

impl IntoResponse for MatrixError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(self)).into_response()
    }
}
