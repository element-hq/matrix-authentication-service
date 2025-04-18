// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{Json, extract::State, response::IntoResponse};
use chrono::Duration;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::{SiteConfig, TokenFormatError, TokenType};
use mas_storage::{
    BoxClock, BoxRepository, BoxRng, Clock,
    compat::{CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository},
};
use serde::{Deserialize, Serialize};
use serde_with::{DurationMilliSeconds, serde_as};
use thiserror::Error;
use ulid::Ulid;

use super::MatrixError;
use crate::{BoundActivityTracker, impl_from_error_for_route};

#[derive(Debug, Deserialize)]
pub struct RequestBody {
    refresh_token: String,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("invalid token")]
    InvalidToken(#[from] TokenFormatError),

    #[error("unknown token")]
    UnknownToken,

    #[error("invalid token type {0}, expected a compat refresh token")]
    InvalidTokenType(TokenType),

    #[error("refresh token already consumed {0}")]
    RefreshTokenConsumed(Ulid),

    #[error("invalid compat session {0}")]
    InvalidSession(Ulid),

    #[error("unknown comapt session {0}")]
    UnknownSession(Ulid),
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(self, Self::Internal(_) | Self::UnknownSession(_));
        let response = match self {
            Self::Internal(_) | Self::UnknownSession(_) => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::InvalidToken(_)
            | Self::UnknownToken
            | Self::InvalidTokenType(_)
            | Self::InvalidSession(_)
            | Self::RefreshTokenConsumed(_) => MatrixError {
                errcode: "M_UNKNOWN_TOKEN",
                error: "Invalid refresh token",
                status: StatusCode::UNAUTHORIZED,
            },
        };

        (sentry_event_id, response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);

#[serde_as]
#[derive(Debug, Serialize)]
pub struct ResponseBody {
    access_token: String,
    refresh_token: String,
    #[serde_as(as = "DurationMilliSeconds<i64>")]
    expires_in_ms: Duration,
}

#[tracing::instrument(name = "handlers.compat.refresh.post", skip_all)]
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
        return Err(RouteError::InvalidTokenType(token_type));
    }

    let refresh_token = repo
        .compat_refresh_token()
        .find_by_token(&input.refresh_token)
        .await?
        .ok_or(RouteError::UnknownToken)?;

    if !refresh_token.is_valid() {
        return Err(RouteError::RefreshTokenConsumed(refresh_token.id));
    }

    let session = repo
        .compat_session()
        .lookup(refresh_token.session_id)
        .await?
        .ok_or(RouteError::UnknownSession(refresh_token.session_id))?;

    if !session.is_valid() {
        return Err(RouteError::InvalidSession(refresh_token.session_id));
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
