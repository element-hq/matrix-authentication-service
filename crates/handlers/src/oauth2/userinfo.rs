// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use hyper::StatusCode;
use mas_axum_utils::{
    jwt::JwtResponse,
    record_error,
    user_authorization::{AuthorizationVerificationError, UserAuthorization},
};
use mas_jose::{
    constraints::Constrainable,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use mas_keystore::Keystore;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng, oauth2::OAuth2ClientRepository};
use serde::Serialize;
use serde_with::skip_serializing_none;
use thiserror::Error;
use ulid::Ulid;

use crate::{BoundActivityTracker, impl_from_error_for_route};

#[skip_serializing_none]
#[derive(Serialize)]
struct UserInfo {
    sub: String,
    username: String,
}

#[derive(Serialize)]
struct SignedUserInfo {
    iss: String,
    aud: String,
    #[serde(flatten)]
    user_info: UserInfo,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("failed to authenticate")]
    AuthorizationVerificationError(
        #[from] AuthorizationVerificationError<mas_storage::RepositoryError>,
    ),

    #[error("session is not allowed to access the userinfo endpoint")]
    Unauthorized,

    #[error("no suitable key found for signing")]
    InvalidSigningKey,

    #[error("failed to load client {0}")]
    NoSuchClient(Ulid),

    #[error("failed to load user {0}")]
    NoSuchUser(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_keystore::WrongAlgorithmError);
impl_from_error_for_route!(mas_jose::jwt::JwtSignatureError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(
            self,
            Self::Internal(_)
                | Self::InvalidSigningKey
                | Self::NoSuchClient(_)
                | Self::NoSuchUser(_)
        );
        let response = match self {
            Self::Internal(_)
            | Self::InvalidSigningKey
            | Self::NoSuchClient(_)
            | Self::NoSuchUser(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
            Self::AuthorizationVerificationError(_) | Self::Unauthorized => {
                StatusCode::UNAUTHORIZED.into_response()
            }
        };

        (sentry_event_id, response).into_response()
    }
}

#[tracing::instrument(name = "handlers.oauth2.userinfo.get", skip_all)]
pub async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    State(key_store): State<Keystore>,
    user_authorization: UserAuthorization,
) -> Result<Response, RouteError> {
    let session = user_authorization.protected(&mut repo, &clock).await?;

    // This endpoint requires the `openid` scope.
    if !session.scope.contains("openid") {
        return Err(RouteError::Unauthorized);
    }

    // Fail if the session is not associated with a user.
    let Some(user_id) = session.user_id else {
        return Err(RouteError::Unauthorized);
    };

    activity_tracker
        .record_oauth2_session(&clock, &session)
        .await;

    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(RouteError::NoSuchUser(user_id))?;

    let user_info = UserInfo {
        sub: user.sub.clone(),
        username: user.username.clone(),
    };

    let client = repo
        .oauth2_client()
        .lookup(session.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient(session.client_id))?;

    repo.save().await?;

    if let Some(alg) = client.userinfo_signed_response_alg {
        let key = key_store
            .signing_key_for_algorithm(&alg)
            .ok_or(RouteError::InvalidSigningKey)?;

        let signer = key.params().signing_key_for_alg(&alg)?;
        let header = JsonWebSignatureHeader::new(alg)
            .with_kid(key.kid().ok_or(RouteError::InvalidSigningKey)?);

        let user_info = SignedUserInfo {
            iss: url_builder.oidc_issuer().to_string(),
            aud: client.client_id,
            user_info,
        };

        let token = Jwt::sign_with_rng(&mut rng, header, user_info, &signer)?;
        Ok(JwtResponse(token).into_response())
    } else {
        Ok(Json(user_info).into_response())
    }
}
