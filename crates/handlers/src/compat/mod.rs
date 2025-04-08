// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    Json,
    body::Bytes,
    extract::{
        Request,
        rejection::{BytesRejection, FailedToBufferBody},
    },
    response::IntoResponse,
};
use hyper::{StatusCode, header};
use mas_axum_utils::sentry::SentryEventID;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

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

#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct MatrixJsonBody<T>(pub T);

#[derive(Debug, Error)]
pub enum MatrixJsonBodyRejection {
    #[error("Invalid Content-Type header: expected application/json")]
    InvalidContentType,

    #[error("Invalid Content-Type header: expected application/json, got {0}")]
    ContentTypeNotJson(mime::Mime),

    #[error("Failed to read request body")]
    BytesRejection(#[from] BytesRejection),

    #[error("Invalid JSON document")]
    Json(#[from] serde_json::Error),
}

impl IntoResponse for MatrixJsonBodyRejection {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        let response = match self {
            Self::InvalidContentType | Self::ContentTypeNotJson(_) => MatrixError {
                errcode: "M_NOT_JSON",
                error: "Invalid Content-Type header: expected application/json",
                status: StatusCode::BAD_REQUEST,
            },

            Self::BytesRejection(BytesRejection::FailedToBufferBody(
                FailedToBufferBody::LengthLimitError(_),
            )) => MatrixError {
                errcode: "M_TOO_LARGE",
                error: "Request body too large",
                status: StatusCode::PAYLOAD_TOO_LARGE,
            },

            Self::BytesRejection(BytesRejection::FailedToBufferBody(
                FailedToBufferBody::UnknownBodyError(_),
            )) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Failed to read request body",
                status: StatusCode::BAD_REQUEST,
            },

            Self::BytesRejection(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Unknown error while reading request body",
                status: StatusCode::BAD_REQUEST,
            },

            Self::Json(err) if err.is_data() => MatrixError {
                errcode: "M_BAD_JSON",
                error: "JSON fields are not valid",
                status: StatusCode::BAD_REQUEST,
            },

            Self::Json(_) => MatrixError {
                errcode: "M_NOT_JSON",
                error: "Body is not a valid JSON document",
                status: StatusCode::BAD_REQUEST,
            },
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

impl<T, S> axum::extract::FromRequest<S> for MatrixJsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = MatrixJsonBodyRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Matrix spec says it's optional to send a Content-Type header, so we
        // only check it if it's present
        if let Some(content_type) = req.headers().get(header::CONTENT_TYPE) {
            let Ok(content_type) = content_type.to_str() else {
                return Err(MatrixJsonBodyRejection::InvalidContentType);
            };

            let Ok(mime) = content_type.parse::<mime::Mime>() else {
                return Err(MatrixJsonBodyRejection::InvalidContentType);
            };

            let is_json_content_type = mime.type_() == "application"
                && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"));

            if !is_json_content_type {
                return Err(MatrixJsonBodyRejection::ContentTypeNotJson(mime));
            }
        }

        let bytes = Bytes::from_request(req, state).await?;

        let value: T = serde_json::from_slice(&bytes)?;

        Ok(Self(value))
    }
}
