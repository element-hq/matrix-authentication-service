// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{extract::State, response::IntoResponse, Json};
use chrono::Duration;
use hyper::StatusCode;
use mas_axum_utils::sentry::SentryEventID;
use mas_data_model::{SiteConfig, TokenFormatError, TokenType};
use mas_storage::{
    compat::{CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository},
    BoxClock, BoxRepository, BoxRng, Clock,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationMilliSeconds};
use thiserror::Error;

use super::MatrixError;
use crate::{impl_from_error_for_route, BoundActivityTracker};

#[derive(Debug, Deserialize)]
pub struct RequestBody {
    refresh_token: String,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("invalid token")]
    InvalidToken,

    #[error("refresh token already consumed")]
    RefreshTokenConsumed,

    #[error("invalid session")]
    InvalidSession,

    #[error("unknown session")]
    UnknownSession,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        let response = match self {
            Self::Internal(_) | Self::UnknownSession => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::InvalidToken | Self::InvalidSession | Self::RefreshTokenConsumed => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid refresh token",
                status: StatusCode::UNAUTHORIZED,
            },
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl From<TokenFormatError> for RouteError {
    fn from(_e: TokenFormatError) -> Self {
        Self::InvalidToken
    }
}

#[serde_as]
#[derive(Debug, Serialize)]
pub struct ResponseBody {
    access_token: String,
    refresh_token: String,
    #[serde_as(as = "DurationMilliSeconds<i64>")]
    expires_in_ms: Duration,
}

#[tracing::instrument(name = "handlers.compat.refresh.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    State(site_config): State<SiteConfig>,
    Json(input): Json<RequestBody>,
) -> Result<impl IntoResponse, RouteError> {
    let token_type = TokenType::check(&input.refresh_token)?;

    if token_type != TokenType::CompatRefreshToken {
        return Err(RouteError::InvalidToken);
    }

    let refresh_token = repo
        .compat_refresh_token()
        .find_by_token(&input.refresh_token)
        .await?
        .ok_or(RouteError::InvalidToken)?;

    if !refresh_token.is_valid() {
        return Err(RouteError::RefreshTokenConsumed);
    }

    let session = repo
        .compat_session()
        .lookup(refresh_token.session_id)
        .await?
        .ok_or(RouteError::UnknownSession)?;

    if !session.is_valid() {
        return Err(RouteError::InvalidSession);
    }

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    let access_token = repo
        .compat_access_token()
        .lookup(refresh_token.access_token_id)
        .await?
        .filter(|t| t.is_valid(clock.now()));

    let new_refresh_token_str = TokenType::CompatRefreshToken.generate(&mut rng);
    let new_access_token_str = TokenType::CompatAccessToken.generate(&mut rng);

    let expires_in = site_config.compat_token_ttl;
    let new_access_token = repo
        .compat_access_token()
        .add(
            &mut rng,
            &clock,
            &session,
            new_access_token_str,
            Some(expires_in),
        )
        .await?;
    let new_refresh_token = repo
        .compat_refresh_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &new_access_token,
            new_refresh_token_str,
        )
        .await?;

    repo.compat_refresh_token()
        .consume(&clock, refresh_token)
        .await?;

    if let Some(access_token) = access_token {
        repo.compat_access_token()
            .expire(&clock, access_token)
            .await?;
    }

    repo.save().await?;

    Ok(Json(ResponseBody {
        access_token: new_access_token.token,
        refresh_token: new_refresh_token.token,
        expires_in_ms: expires_in,
    }))
}
