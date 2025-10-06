// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{Json, extract::State, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    record_error,
};
use mas_data_model::{BoxClock, BoxRng, BrowserSession, TokenType};
use mas_iana::oauth::OAuthTokenTypeHint;
use mas_keystore::Encrypter;
use mas_storage::{
    BoxRepository, RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::RevocationRequest,
};
use thiserror::Error;
use ulid::Ulid;

use crate::{BoundActivityTracker, impl_from_error_for_route};

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed")]
    ClientNotAllowed,

    #[error("invalid client credentials for client {client_id}")]
    InvalidClientCredentials {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },

    #[error("could not verify client credentials for client {client_id}")]
    ClientCredentialsVerification {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },

    #[error("client is unauthorized")]
    UnauthorizedClient,

    #[error("unsupported token type")]
    UnsupportedTokenType,

    #[error("unknown token")]
    UnknownToken,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let response = match self {
            Self::Internal(_) | Self::ClientCredentialsVerification { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            )
                .into_response(),

            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            )
                .into_response(),

            Self::ClientNotFound | Self::InvalidClientCredentials { .. } => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            )
                .into_response(),

            Self::ClientNotAllowed | Self::UnauthorizedClient => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::UnauthorizedClient)),
            )
                .into_response(),

            Self::UnsupportedTokenType => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::UnsupportedTokenType)),
            )
                .into_response(),

            // If the token is unknown, we still return a 200 OK response.
            Self::UnknownToken => StatusCode::OK.into_response(),
        };

        (sentry_event_id, response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl From<mas_data_model::TokenFormatError> for RouteError {
    fn from(_e: mas_data_model::TokenFormatError) -> Self {
        Self::UnknownToken
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.revoke.post",
    fields(client.id = client_authorization.client_id()),
    skip_all,
)]
pub(crate) async fn post(
    clock: BoxClock,
    mut rng: BoxRng,
    State(http_client): State<reqwest::Client>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    State(encrypter): State<Encrypter>,
    client_authorization: ClientAuthorization<RevocationRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed)?;

    client_authorization
        .credentials
        .verify(&http_client, &encrypter, method, &client)
        .await
        .map_err(|err| {
            if err.is_internal() {
                RouteError::ClientCredentialsVerification {
                    client_id: client.id,
                    source: err,
                }
            } else {
                RouteError::InvalidClientCredentials {
                    client_id: client.id,
                    source: err,
                }
            }
        })?;

    let Some(form) = client_authorization.form else {
        return Err(RouteError::BadRequest);
    };

    let token_type = TokenType::check(&form.token)?;

    // Find the ID of the session to end.
    let session_id = match (form.token_type_hint, token_type) {
        (Some(OAuthTokenTypeHint::AccessToken) | None, TokenType::AccessToken) => {
            let access_token = repo
                .oauth2_access_token()
                .find_by_token(&form.token)
                .await?
                .ok_or(RouteError::UnknownToken)?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::UnknownToken);
            }
            access_token.session_id
        }

        (Some(OAuthTokenTypeHint::RefreshToken) | None, TokenType::RefreshToken) => {
            let refresh_token = repo
                .oauth2_refresh_token()
                .find_by_token(&form.token)
                .await?
                .ok_or(RouteError::UnknownToken)?;

            if !refresh_token.is_valid() {
                return Err(RouteError::UnknownToken);
            }

            refresh_token.session_id
        }

        // This case can happen if there is a mismatch between the token type hint and the guessed
        // token type or if the token was a compat access/refresh token. In those cases, we return
        // an unknown token error.
        (Some(OAuthTokenTypeHint::AccessToken | OAuthTokenTypeHint::RefreshToken) | None, _) => {
            return Err(RouteError::UnknownToken);
        }

        (Some(_), _) => return Err(RouteError::UnsupportedTokenType),
    };

    let session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::UnknownToken)?;

    // Check that the session is still valid.
    if !session.is_valid() {
        return Err(RouteError::UnknownToken);
    }

    // Check that the client ending the session is the same as the client that
    // created it.
    if client.id != session.client_id {
        return Err(RouteError::UnauthorizedClient);
    }

    activity_tracker
        .record_oauth2_session(&clock, &session)
        .await;

    // If the session is associated with a user, make sure we schedule a device
    // deletion job for all the devices associated with the session.
    if let Some(user_id) = session.user_id {
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

    // :tchap:
    let maybe_user_session_id = session.user_session_id;
    // :tchap: end

    // Now that we checked everything, we can end the session.
    repo.oauth2_session().finish(&clock, session).await?;

    // :tchap:
    end_browser_session(clock, &mut repo, maybe_user_session_id, activity_tracker).await?;
    // :tchap: end

    repo.save().await?;

    Ok(())
}

// :tchap:
/// Terminates a browser session
///
/// # Parameters
/// * `clock` - Clock used for auditing actions
/// * `repo` - Repository access
/// * `maybe_user_session_id` - user browser session identifier
/// * `activity_tracker` -  Tracker used to record action on the browser session
///
/// TODO :
/// - this function should move in crates/tchap/lib.rs
/// - to be able to move this function, `BoundActivityTracker` should be moved
///   to data-model crates or another handler-model
///
/// # Returns
/// Option<`mas_data_model::BrowserSession`> - The user's browser that has been
/// terminated if exists
pub async fn end_browser_session(
    clock: BoxClock,
    repo: &mut BoxRepository,
    maybe_user_session_id: Option<Ulid>,
    activity_tracker: BoundActivityTracker,
) -> Result<Option<BrowserSession>, mas_storage::RepositoryError> {
    if let Some(user_session_id) = maybe_user_session_id {
        let maybe_session = repo.browser_session().lookup(user_session_id).await?;
        if let Some(browser_session) = maybe_session
            && browser_session.finished_at.is_none()
        {
            activity_tracker
                .record_browser_session(&clock, &browser_session)
                .await;
            return Ok(Some(
                repo.browser_session()
                    .finish(&clock, browser_session)
                    .await?,
            ));
        }
    }
    Ok(None)
}
// :tchap: end

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::Request;
    use mas_data_model::{AccessToken, RefreshToken};
    use mas_router::SimpleRoute;
    use mas_storage::RepositoryAccess;
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        requests::AccessTokenResponse,
        scope::{OPENID, Scope},
    };
    use sqlx::PgPool;

    use super::*;
    use crate::{
        oauth2::generate_token_pair,
        test_utils::{RequestBuilderExt, ResponseExt, TestState, setup},
    };

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_revoke_access_token(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let client_registration: ClientRegistrationResponse = response.json();

        let client_id = client_registration.client_id;
        let client_secret = client_registration.client_secret.unwrap();

        // Let's provision a user and create a session for them. This part is hard to
        // test with just HTTP requests, so we'll use the repository directly.
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();

        // Lookup the client in the database.
        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();

        let session = repo
            .oauth2_session()
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();

        let (AccessToken { access_token, .. }, RefreshToken { refresh_token, .. }) =
            generate_token_pair(
                &mut state.rng(),
                &state.clock,
                &mut repo,
                &session,
                Duration::microseconds(5 * 60 * 1000 * 1000),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Check that the token is valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Now let's revoke the access token.
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": access_token,
            "token_type_hint": "access_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        // Check that the token is no longer valid
        assert!(!state.is_access_token_valid(&access_token).await);

        // Revoking a second time shouldn't fail
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": access_token,
            "token_type_hint": "access_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        // Try using the refresh token to get a new access token, it should fail.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        // Now try with a new grant, and by revoking the refresh token instead
        let mut repo = state.repository().await.unwrap();
        let session = repo
            .oauth2_session()
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();

        let (AccessToken { access_token, .. }, RefreshToken { refresh_token, .. }) =
            generate_token_pair(
                &mut state.rng(),
                &state.clock,
                &mut repo,
                &session,
                Duration::microseconds(5 * 60 * 1000 * 1000),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Use the refresh token to get a new access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let old_access_token = access_token;
        let old_refresh_token = refresh_token;
        let AccessTokenResponse {
            access_token,
            refresh_token,
            ..
        } = response.json();
        assert!(state.is_access_token_valid(&access_token).await);
        assert!(!state.is_access_token_valid(&old_access_token).await);

        // Revoking the old access token shouldn't do anything.
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": old_access_token,
            "token_type_hint": "access_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        assert!(state.is_access_token_valid(&access_token).await);

        // Revoking the old refresh token shouldn't do anything.
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": old_refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        assert!(state.is_access_token_valid(&access_token).await);

        // Revoking the new refresh token should invalidate the session
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        assert!(!state.is_access_token_valid(&access_token).await);
    }
}
