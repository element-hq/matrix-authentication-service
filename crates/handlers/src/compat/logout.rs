// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{response::IntoResponse, Json};
use axum_extra::typed_header::TypedHeader;
use headers::{authorization::Bearer, Authorization};
use hyper::StatusCode;
use mas_axum_utils::sentry::SentryEventID;
use mas_data_model::TokenType;
use mas_storage::{
    compat::{CompatAccessTokenRepository, CompatSessionRepository},
    job::JobRepositoryExt,
    queue::SyncDevicesJob,
    BoxClock, BoxRepository, Clock, RepositoryAccess,
};
use thiserror::Error;

use super::MatrixError;
use crate::{impl_from_error_for_route, BoundActivityTracker};

#[derive(Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Missing access token")]
    MissingAuthorization,

    #[error("Invalid token format")]
    TokenFormat(#[from] mas_data_model::TokenFormatError),

    #[error("Invalid access token")]
    InvalidAuthorization,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        let response = match self {
            Self::Internal(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::MissingAuthorization => MatrixError {
                errcode: "M_MISSING_TOKEN",
                error: "Missing access token",
                status: StatusCode::UNAUTHORIZED,
            },
            Self::InvalidAuthorization | Self::TokenFormat(_) => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid access token",
                status: StatusCode::UNAUTHORIZED,
            },
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

#[tracing::instrument(name = "handlers.compat.logout.post", skip_all, err)]
pub(crate) async fn post(
    clock: BoxClock,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    maybe_authorization: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<impl IntoResponse, RouteError> {
    let TypedHeader(authorization) = maybe_authorization.ok_or(RouteError::MissingAuthorization)?;

    let token = authorization.token();
    let token_type = TokenType::check(token)?;

    if token_type != TokenType::CompatAccessToken {
        return Err(RouteError::InvalidAuthorization);
    }

    let token = repo
        .compat_access_token()
        .find_by_token(token)
        .await?
        .filter(|t| t.is_valid(clock.now()))
        .ok_or(RouteError::InvalidAuthorization)?;

    let session = repo
        .compat_session()
        .lookup(token.session_id)
        .await?
        .filter(|s| s.is_valid())
        .ok_or(RouteError::InvalidAuthorization)?;

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    let user = repo
        .user()
        .lookup(session.user_id)
        .await?
        // XXX: this is probably not the right error
        .ok_or(RouteError::InvalidAuthorization)?;

    // Schedule a job to sync the devices of the user with the homeserver
    repo.job().schedule_job(SyncDevicesJob::new(&user)).await?;

    repo.compat_session().finish(&clock, session).await?;

    repo.save().await?;

    Ok(Json(serde_json::json!({})))
}
