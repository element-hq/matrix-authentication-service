// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::Query;
use hyper::StatusCode;
use mas_axum_utils::{SessionInfoExt, cookies::CookieJar, record_error};
use mas_data_model::{BoxClock, BoxRng, Clock};
use mas_keystore::Keystore;
use mas_oidc_client::{
    error::IdTokenError,
    requests::jose::{JwtVerificationData, verify_id_token},
};
use mas_router::UrlBuilder;
use mas_storage::{
    BoxRepository, RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    user::BrowserSessionRepository,
};
use oauth2_types::errors::{ClientError, ClientErrorCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{BoundActivityTracker, impl_from_error_for_route};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct EndSessionParam {
    id_token_hint: String,
    post_logout_redirect_uri: String,
}

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("client not found")]
    ClientNotFound,

    #[error("client is unauthorized")]
    UnauthorizedClient,

    // #[error("unsupported token type")]
    // UnsupportedTokenType,
    #[error("unknown token")]
    UnknownToken,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let response = match self {
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            )
                .into_response(),

            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            )
                .into_response(),

            Self::ClientNotFound => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            )
                .into_response(),

            // Self::ClientNotAllowed |
            Self::UnauthorizedClient => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::UnauthorizedClient)),
            )
                .into_response(),

            // Self::UnsupportedTokenType => (
            //     StatusCode::BAD_REQUEST,
            //     Json(ClientError::from(ClientErrorCode::UnsupportedTokenType)),
            // )
            //     .into_response(),

            // If the token is unknown, we still return a 200 OK response.
            Self::UnknownToken => StatusCode::OK.into_response(),
        };

        (sentry_event_id, response).into_response()
    }
}

impl From<IdTokenError> for RouteError {
    fn from(_e: IdTokenError) -> Self {
        Self::UnknownToken
    }
}

#[tracing::instrument(name = "handlers.oauth2.end_session.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(key_store): State<Keystore>,
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(params): Query<EndSessionParam>,
    cookie_jar: CookieJar,
) -> Result<Response, RouteError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let browser_session_id = session_info
        .current_session_id()
        .ok_or(RouteError::BadRequest)?;

    let browser_session = repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .ok_or(RouteError::BadRequest)?;

    let oauth_session = repo
        .oauth2_session()
        .find_by_browser_session(browser_session.id)
        .await?
        .ok_or(RouteError::BadRequest)?;

    let client = repo
        .oauth2_client()
        .lookup(oauth_session.client_id)
        .await?
        .filter(|client| client.id_token_signed_response_alg.is_some())
        .ok_or(RouteError::ClientNotFound)?;

    let jwks = key_store.public_jwks();
    let issuer: String = url_builder.oidc_issuer().into();

    let id_token_verification_data = JwtVerificationData {
        issuer: Some(&issuer),
        jwks: &jwks,
        signing_algorithm: &client.id_token_signed_response_alg.unwrap(),
        client_id: &client.client_id,
    };

    verify_id_token(
        &params.id_token_hint,
        id_token_verification_data,
        None,
        clock.now(),
    )?;

    // Check that the session is still valid.
    if !oauth_session.is_valid() {
        // If the session is not valid, we redirect to post logout uri
        return Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response());
    }

    // Check that the client ending the session is the same as the client that
    // created it.
    if client.id != oauth_session.client_id {
        return Err(RouteError::UnauthorizedClient);
    }

    activity_tracker
        .record_oauth2_session(&clock, &oauth_session)
        .await;

    // If the session is associated with a user, make sure we schedule a device
    // deletion job for all the devices associated with the session.
    if let Some(user_id) = oauth_session.user_id {
        // Fetch the user
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or(RouteError::UnknownToken)?;

        // Schedule a job to sync the devices of the user with the homeserver
        repo.queue_job()
            .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
            .await?;
    }

    // Now that we checked everything, we can end the session.
    repo.oauth2_session().finish(&clock, oauth_session).await?;

    activity_tracker
        .record_browser_session(&clock, &browser_session)
        .await;
    repo.browser_session()
        .finish(&clock, browser_session)
        .await?;

    repo.save().await?;

    // We always want to clear out the session cookie, even if the session was
    // invalid
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

    Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response())
}
