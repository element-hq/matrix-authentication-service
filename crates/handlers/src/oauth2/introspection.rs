// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::{Arc, LazyLock};

use axum::{Json, extract::State, http::HeaderValue, response::IntoResponse};
use hyper::{HeaderMap, StatusCode};
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    record_error,
};
use mas_data_model::{Device, TokenFormatError, TokenType};
use mas_iana::oauth::{OAuthClientAuthenticationMethod, OAuthTokenTypeHint};
use mas_keystore::Encrypter;
use mas_matrix::HomeserverConnection;
use mas_storage::{
    BoxClock, BoxRepository, Clock,
    compat::{CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository},
    oauth2::{OAuth2AccessTokenRepository, OAuth2RefreshTokenRepository, OAuth2SessionRepository},
    user::UserRepository,
};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{IntrospectionRequest, IntrospectionResponse},
    scope::ScopeToken,
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use thiserror::Error;
use ulid::Ulid;

use crate::{ActivityTracker, METER, impl_from_error_for_route};

static INTROSPECTION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.oauth2.introspection_request")
        .with_description("Number of OAuth 2.0 introspection requests")
        .with_unit("{request}")
        .build()
});

const KIND: Key = Key::from_static_str("kind");
const ACTIVE: Key = Key::from_static_str("active");

#[derive(Debug, Error)]
pub enum RouteError {
    /// An internal error occurred.
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The client could not be found.
    #[error("could not find client")]
    ClientNotFound,

    /// The client is not allowed to introspect.
    #[error("client {0} is not allowed to introspect")]
    NotAllowed(Ulid),

    /// The token type is not the one expected.
    #[error("unexpected token type")]
    UnexpectedTokenType,

    /// The overall token format is invalid.
    #[error("invalid token format")]
    InvalidTokenFormat(#[from] TokenFormatError),

    /// The token could not be found in the database.
    #[error("unknown {0}")]
    UnknownToken(TokenType),

    /// The token is not valid.
    #[error("{0} is not valid")]
    InvalidToken(TokenType),

    /// The OAuth session is not valid.
    #[error("invalid oauth session {0}")]
    InvalidOAuthSession(Ulid),

    /// The OAuth session could not be found in the database.
    #[error("unknown oauth session {0}")]
    CantLoadOAuthSession(Ulid),

    /// The compat session is not valid.
    #[error("invalid compat session {0}")]
    InvalidCompatSession(Ulid),

    /// The compat session could not be found in the database.
    #[error("unknown compat session {0}")]
    CantLoadCompatSession(Ulid),

    /// The Device ID in the compat session can't be encoded as a scope
    #[error("device ID contains characters that are not allowed in a scope")]
    CantEncodeDeviceID(#[from] mas_data_model::ToScopeTokenError),

    #[error("invalid user {0}")]
    InvalidUser(Ulid),

    #[error("unknown user {0}")]
    CantLoadUser(Ulid),

    #[error("bad request")]
    BadRequest,

    #[error("failed to verify token")]
    FailedToVerifyToken(#[source] anyhow::Error),

    #[error(transparent)]
    ClientCredentialsVerification(#[from] CredentialsVerificationError),

    #[error("bearer token presented is invalid")]
    InvalidBearerToken,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(
            self,
            Self::Internal(_)
                | Self::CantLoadCompatSession(_)
                | Self::CantLoadOAuthSession(_)
                | Self::CantLoadUser(_)
                | Self::FailedToVerifyToken(_)
        );

        let response = match self {
            e @ (Self::Internal(_)
            | Self::CantLoadCompatSession(_)
            | Self::CantLoadOAuthSession(_)
            | Self::CantLoadUser(_)
            | Self::FailedToVerifyToken(_)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    ClientError::from(ClientErrorCode::ServerError).with_description(e.to_string()),
                ),
            )
                .into_response(),
            Self::ClientNotFound => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            )
                .into_response(),
            Self::ClientCredentialsVerification(e) => (
                StatusCode::UNAUTHORIZED,
                Json(
                    ClientError::from(ClientErrorCode::InvalidClient)
                        .with_description(e.to_string()),
                ),
            )
                .into_response(),
            e @ Self::InvalidBearerToken => (
                StatusCode::UNAUTHORIZED,
                Json(
                    ClientError::from(ClientErrorCode::AccessDenied)
                        .with_description(e.to_string()),
                ),
            )
                .into_response(),

            Self::UnknownToken(_)
            | Self::UnexpectedTokenType
            | Self::InvalidToken(_)
            | Self::InvalidUser(_)
            | Self::InvalidCompatSession(_)
            | Self::InvalidOAuthSession(_)
            | Self::InvalidTokenFormat(_)
            | Self::CantEncodeDeviceID(_) => {
                INTROSPECTION_COUNTER.add(1, &[KeyValue::new(ACTIVE.clone(), false)]);

                Json(INACTIVE).into_response()
            }

            Self::NotAllowed(_) => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::AccessDenied)),
            )
                .into_response(),

            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            )
                .into_response(),
        };

        (sentry_event_id, response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);

const INACTIVE: IntrospectionResponse = IntrospectionResponse {
    active: false,
    scope: None,
    client_id: None,
    username: None,
    token_type: None,
    exp: None,
    expires_in: None,
    iat: None,
    nbf: None,
    sub: None,
    aud: None,
    iss: None,
    jti: None,
    device_id: None,
};

const API_SCOPE: ScopeToken = ScopeToken::from_static("urn:matrix:org.matrix.msc2967.client:api:*");
const SYNAPSE_ADMIN_SCOPE: ScopeToken = ScopeToken::from_static("urn:synapse:admin:*");

#[tracing::instrument(
    name = "handlers.oauth2.introspection.post",
    fields(client.id = credentials.client_id()),
    skip_all,
)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn post(
    clock: BoxClock,
    State(http_client): State<reqwest::Client>,
    mut repo: BoxRepository,
    activity_tracker: ActivityTracker,
    State(encrypter): State<Encrypter>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    headers: HeaderMap,
    ClientAuthorization { credentials, form }: ClientAuthorization<IntrospectionRequest>,
) -> Result<impl IntoResponse, RouteError> {
    if let Some(token) = credentials.bearer_token() {
        // If the client presented a bearer token, we check with the homeserver
        // configuration if it is allowed to use the introspection endpoint
        if !homeserver
            .verify_token(token)
            .await
            .map_err(RouteError::FailedToVerifyToken)?
        {
            return Err(RouteError::InvalidBearerToken);
        }
    } else {
        // Otherwise, it presented regular client credentials, so we verify them
        let client = credentials
            .fetch(&mut repo)
            .await?
            .ok_or(RouteError::ClientNotFound)?;

        // Only confidential clients are allowed to introspect
        let method = match &client.token_endpoint_auth_method {
            None | Some(OAuthClientAuthenticationMethod::None) => {
                return Err(RouteError::NotAllowed(client.id));
            }
            Some(c) => c,
        };

        credentials
            .verify(&http_client, &encrypter, method, &client)
            .await?;
    }

    let Some(form) = form else {
        return Err(RouteError::BadRequest);
    };

    let token = &form.token;
    let token_type = TokenType::check(token)?;
    if let Some(hint) = form.token_type_hint {
        if token_type != hint {
            return Err(RouteError::UnexpectedTokenType);
        }
    }

    // Not all device IDs can be encoded as scope. On OAuth 2.0 sessions, we
    // don't have this problem, as the device ID *is* already encoded as a scope.
    // But on compatibility sessions, it's possible to have device IDs with
    // spaces in them, or other weird characters.
    // In those cases, we prefer explicitly giving out the device ID as a separate
    // field. The client introspecting tells us whether it supports having the
    // device ID as a separate field through this header.
    let supports_explicit_device_id =
        headers.get("X-MAS-Supports-Device-Id") == Some(&HeaderValue::from_static("1"));

    // XXX: we should get the IP from the client introspecting the token
    let ip = None;

    let reply = match token_type {
        TokenType::AccessToken => {
            let mut access_token = repo
                .oauth2_access_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::AccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::InvalidToken(TokenType::AccessToken));
            }

            let session = repo
                .oauth2_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadOAuthSession(access_token.session_id))?;

            if !session.is_valid() {
                return Err(RouteError::InvalidOAuthSession(session.id));
            }

            // If this is the first time we're using this token, mark it as used
            if !access_token.is_used() {
                access_token = repo
                    .oauth2_access_token()
                    .mark_used(&clock, access_token)
                    .await?;
            }

            // The session might not have a user on it (for Client Credentials grants for
            // example), so we're optionally fetching the user
            let (sub, username) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(RouteError::CantLoadUser(user_id))?;

                if !user.is_valid() {
                    return Err(RouteError::InvalidUser(user.id));
                }

                (Some(user.sub), Some(user.username))
            } else {
                (None, None)
            };

            activity_tracker
                .record_oauth2_session(&clock, &session, ip)
                .await;

            INTROSPECTION_COUNTER.add(
                1,
                &[
                    KeyValue::new(KIND, "oauth2_access_token"),
                    KeyValue::new(ACTIVE, true),
                ],
            );

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client_id.to_string()),
                username,
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                expires_in: access_token
                    .expires_at
                    .map(|expires_at| expires_at.signed_duration_since(clock.now())),
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub,
                aud: None,
                iss: None,
                jti: Some(access_token.jti()),
                device_id: None,
            }
        }

        TokenType::RefreshToken => {
            let refresh_token = repo
                .oauth2_refresh_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::RefreshToken))?;

            if !refresh_token.is_valid() {
                return Err(RouteError::InvalidToken(TokenType::RefreshToken));
            }

            let session = repo
                .oauth2_session()
                .lookup(refresh_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadOAuthSession(refresh_token.session_id))?;

            if !session.is_valid() {
                return Err(RouteError::InvalidOAuthSession(session.id));
            }

            // The session might not have a user on it (for Client Credentials grants for
            // example), so we're optionally fetching the user
            let (sub, username) = if let Some(user_id) = session.user_id {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .ok_or(RouteError::CantLoadUser(user_id))?;

                if !user.is_valid() {
                    return Err(RouteError::InvalidUser(user.id));
                }

                (Some(user.sub), Some(user.username))
            } else {
                (None, None)
            };

            activity_tracker
                .record_oauth2_session(&clock, &session, ip)
                .await;

            INTROSPECTION_COUNTER.add(
                1,
                &[
                    KeyValue::new(KIND, "oauth2_refresh_token"),
                    KeyValue::new(ACTIVE, true),
                ],
            );

            IntrospectionResponse {
                active: true,
                scope: Some(session.scope),
                client_id: Some(session.client_id.to_string()),
                username,
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                expires_in: None,
                iat: Some(refresh_token.created_at),
                nbf: Some(refresh_token.created_at),
                sub,
                aud: None,
                iss: None,
                jti: Some(refresh_token.jti()),
                device_id: None,
            }
        }

        TokenType::CompatAccessToken => {
            let access_token = repo
                .compat_access_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::CompatAccessToken))?;

            if !access_token.is_valid(clock.now()) {
                return Err(RouteError::InvalidToken(TokenType::CompatAccessToken));
            }

            let session = repo
                .compat_session()
                .lookup(access_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadCompatSession(access_token.session_id))?;

            if !session.is_valid() {
                return Err(RouteError::InvalidCompatSession(session.id));
            }

            let user = repo
                .user()
                .lookup(session.user_id)
                .await?
                .ok_or(RouteError::CantLoadUser(session.user_id))?;

            if !user.is_valid() {
                return Err(RouteError::InvalidUser(user.id))?;
            }

            // Grant the synapse admin scope if the session has the admin flag set.
            let synapse_admin_scope_opt = session.is_synapse_admin.then_some(SYNAPSE_ADMIN_SCOPE);

            // If the client supports explicitly giving the device ID in the response, skip
            // encoding it in the scope
            let device_scope_opt = if supports_explicit_device_id {
                None
            } else {
                session
                    .device
                    .as_ref()
                    .map(Device::to_scope_token)
                    .transpose()?
            };

            let scope = [API_SCOPE]
                .into_iter()
                .chain(device_scope_opt)
                .chain(synapse_admin_scope_opt)
                .collect();

            activity_tracker
                .record_compat_session(&clock, &session, ip)
                .await;

            INTROSPECTION_COUNTER.add(
                1,
                &[
                    KeyValue::new(KIND, "compat_access_token"),
                    KeyValue::new(ACTIVE, true),
                ],
            );

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(user.username),
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: access_token.expires_at,
                expires_in: access_token
                    .expires_at
                    .map(|expires_at| expires_at.signed_duration_since(clock.now())),
                iat: Some(access_token.created_at),
                nbf: Some(access_token.created_at),
                sub: Some(user.sub),
                aud: None,
                iss: None,
                jti: None,
                device_id: session.device.map(Device::into),
            }
        }

        TokenType::CompatRefreshToken => {
            let refresh_token = repo
                .compat_refresh_token()
                .find_by_token(token)
                .await?
                .ok_or(RouteError::UnknownToken(TokenType::CompatRefreshToken))?;

            if !refresh_token.is_valid() {
                return Err(RouteError::InvalidToken(TokenType::CompatRefreshToken));
            }

            let session = repo
                .compat_session()
                .lookup(refresh_token.session_id)
                .await?
                .ok_or(RouteError::CantLoadCompatSession(refresh_token.session_id))?;

            if !session.is_valid() {
                return Err(RouteError::InvalidCompatSession(session.id));
            }

            let user = repo
                .user()
                .lookup(session.user_id)
                .await?
                .ok_or(RouteError::CantLoadUser(session.user_id))?;

            if !user.is_valid() {
                return Err(RouteError::InvalidUser(user.id))?;
            }

            // Grant the synapse admin scope if the session has the admin flag set.
            let synapse_admin_scope_opt = session.is_synapse_admin.then_some(SYNAPSE_ADMIN_SCOPE);

            // If the client supports explicitly giving the device ID in the response, skip
            // encoding it in the scope
            let device_scope_opt = if supports_explicit_device_id {
                None
            } else {
                session
                    .device
                    .as_ref()
                    .map(Device::to_scope_token)
                    .transpose()?
            };

            let scope = [API_SCOPE]
                .into_iter()
                .chain(device_scope_opt)
                .chain(synapse_admin_scope_opt)
                .collect();

            activity_tracker
                .record_compat_session(&clock, &session, ip)
                .await;

            INTROSPECTION_COUNTER.add(
                1,
                &[
                    KeyValue::new(KIND, "compat_refresh_token"),
                    KeyValue::new(ACTIVE, true),
                ],
            );

            IntrospectionResponse {
                active: true,
                scope: Some(scope),
                client_id: Some("legacy".into()),
                username: Some(user.username),
                token_type: Some(OAuthTokenTypeHint::RefreshToken),
                exp: None,
                expires_in: None,
                iat: Some(refresh_token.created_at),
                nbf: Some(refresh_token.created_at),
                sub: Some(user.sub),
                aud: None,
                iss: None,
                jti: None,
                device_id: session.device.map(Device::into),
            }
        }
    };

    repo.save().await?;

    Ok(Json(reply))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::{AccessToken, RefreshToken};
    use mas_iana::oauth::OAuthTokenTypeHint;
    use mas_matrix::{HomeserverConnection, MockHomeserverConnection, ProvisionRequest};
    use mas_router::{OAuth2Introspection, OAuth2RegistrationEndpoint, SimpleRoute};
    use mas_storage::Clock;
    use oauth2_types::{
        errors::{ClientError, ClientErrorCode},
        registration::ClientRegistrationResponse,
        requests::IntrospectionResponse,
        scope::{OPENID, Scope},
    };
    use serde_json::json;
    use sqlx::PgPool;
    use zeroize::Zeroizing;

    use crate::{
        oauth2::generate_token_pair,
        test_utils::{RequestBuilderExt, ResponseExt, TestState, setup},
    };

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_introspect_oauth_tokens(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client which will be used to do introspection requests
        let request = Request::post(OAuth2RegistrationEndpoint::PATH).json(json!({
            "client_uri": "https://introspecting.com/",
            "grant_types": [],
            "token_endpoint_auth_method": "client_secret_basic",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let client: ClientRegistrationResponse = response.json();
        let introspecting_client_id = client.client_id;
        let introspecting_client_secret = client.client_secret.unwrap();

        // Provision a client which will be used to generate tokens
        let request = Request::post(OAuth2RegistrationEndpoint::PATH).json(json!({
            "client_uri": "https://client.com/",
            "redirect_uris": ["https://client.com/"],
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let ClientRegistrationResponse { client_id, .. } = response.json();

        let mut repo = state.repository().await.unwrap();
        // Provision a user and an oauth session
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
            .await
            .unwrap();

        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();

        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
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

        // Now that we have a token, we can introspect it
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": access_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
        assert_eq!(response.username, Some("alice".to_owned()));
        assert_eq!(response.client_id, Some(client_id.clone()));
        assert_eq!(response.token_type, Some(OAuthTokenTypeHint::AccessToken));
        assert_eq!(response.scope, Some(Scope::from_iter([OPENID])));

        // Do the same request, but with a token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": access_token, "token_type_hint": "access_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);

        // Do the same request, but with the wrong token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": access_token, "token_type_hint": "refresh_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active

        // Do the same, but with a refresh token
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": refresh_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
        assert_eq!(response.username, Some("alice".to_owned()));
        assert_eq!(response.client_id, Some(client_id.clone()));
        assert_eq!(response.token_type, Some(OAuthTokenTypeHint::RefreshToken));
        assert_eq!(response.scope, Some(Scope::from_iter([OPENID])));

        // Do the same request, but with a token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": refresh_token, "token_type_hint": "refresh_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);

        // Do the same request, but with the wrong token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": refresh_token, "token_type_hint": "access_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active

        // We should have recorded the session last activity
        state.activity_tracker.flush().await;
        let mut repo = state.repository().await.unwrap();
        let session = repo
            .oauth2_session()
            .lookup(session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.last_active_at, Some(state.clock.now()));

        // And recorded the access token as used
        let access_token_lookup = repo
            .oauth2_access_token()
            .find_by_token(&access_token)
            .await
            .unwrap()
            .unwrap();
        assert!(access_token_lookup.is_used());
        assert_eq!(access_token_lookup.first_used_at, Some(state.clock.now()));
        repo.cancel().await.unwrap();

        // Advance the clock to invalidate the access token
        let old_now = state.clock.now();
        state.clock.advance(Duration::try_hours(1).unwrap());

        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": access_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active anymore

        // That should not have updated the session last activity
        state.activity_tracker.flush().await;
        let mut repo = state.repository().await.unwrap();
        let session = repo
            .oauth2_session()
            .lookup(session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.last_active_at, Some(old_now));
        repo.cancel().await.unwrap();

        // But the refresh token should still be valid
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": refresh_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);

        // But this time, we should have updated the session last activity
        state.activity_tracker.flush().await;
        let mut repo = state.repository().await.unwrap();
        let session = repo
            .oauth2_session()
            .lookup(session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.last_active_at, Some(state.clock.now()));
        repo.cancel().await.unwrap();
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_introspect_compat_tokens(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client which will be used to do introspection requests
        let request = Request::post(OAuth2RegistrationEndpoint::PATH).json(json!({
            "client_uri": "https://introspecting.com/",
            "grant_types": [],
            "token_endpoint_auth_method": "client_secret_basic",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let client: ClientRegistrationResponse = response.json();
        let introspecting_client_id = client.client_id;
        let introspecting_client_secret = client.client_secret.unwrap();

        // Provision a user with a password, so that we can use the password flow
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
            .await
            .unwrap();

        let (version, hashed_password) = state
            .password_manager
            .hash(&mut state.rng(), Zeroizing::new("password".to_owned()))
            .await
            .unwrap();

        repo.user_password()
            .add(
                &mut state.rng(),
                &state.clock,
                &user,
                version,
                hashed_password,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now do a password flow to get an access token and a refresh token
        let request = Request::post("/_matrix/client/v3/login").json(json!({
            "type": "m.login.password",
            "refresh_token": true,
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: serde_json::Value = response.json();
        let access_token = response["access_token"].as_str().unwrap();
        let refresh_token = response["refresh_token"].as_str().unwrap();
        let device_id = response["device_id"].as_str().unwrap();
        let expected_scope: Scope =
            format!("urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:{device_id}")
                .parse()
                .unwrap();

        // Now that we have a token, we can introspect it
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": access_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
        assert_eq!(response.username.as_deref(), Some("alice"));
        assert_eq!(response.client_id.as_deref(), Some("legacy"));
        assert_eq!(response.token_type, Some(OAuthTokenTypeHint::AccessToken));
        assert_eq!(response.scope.as_ref(), Some(&expected_scope));
        assert_eq!(response.device_id.as_deref(), Some(device_id));

        // Check that requesting with X-MAS-Supports-Device-Id removes the device ID
        // from the scope but not from the explicit device_id field
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .header("X-MAS-Supports-Device-Id", "1")
            .form(json!({ "token": access_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
        assert_eq!(response.username.as_deref(), Some("alice"));
        assert_eq!(response.client_id.as_deref(), Some("legacy"));
        assert_eq!(response.token_type, Some(OAuthTokenTypeHint::AccessToken));
        assert_eq!(
            response.scope.map(|s| s.to_string()),
            Some("urn:matrix:org.matrix.msc2967.client:api:*".to_owned())
        );
        assert_eq!(response.device_id.as_deref(), Some(device_id));

        // Do the same request, but with a token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": access_token, "token_type_hint": "access_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);

        // Do the same request, but with the wrong token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": access_token, "token_type_hint": "refresh_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active

        // Do the same, but with a refresh token
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": refresh_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
        assert_eq!(response.username.as_deref(), Some("alice"));
        assert_eq!(response.client_id.as_deref(), Some("legacy"));
        assert_eq!(response.token_type, Some(OAuthTokenTypeHint::RefreshToken));
        assert_eq!(response.scope.as_ref(), Some(&expected_scope));
        assert_eq!(response.device_id.as_deref(), Some(device_id));

        // Do the same request, but with a token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": refresh_token, "token_type_hint": "refresh_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);

        // Do the same request, but with the wrong token_type_hint
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({"token": refresh_token, "token_type_hint": "access_token"}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active

        // Advance the clock to invalidate the access token
        state.clock.advance(Duration::try_hours(1).unwrap());

        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": access_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active); // It shouldn't be active anymore

        // But the refresh token should still be valid
        let request = Request::post(OAuth2Introspection::PATH)
            .basic_auth(&introspecting_client_id, &introspecting_client_secret)
            .form(json!({ "token": refresh_token }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(response.active);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_introspect_with_bearer_token(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Check that talking to the introspection endpoint with the bearer token from
        // the MockHomeserverConnection doens't error out
        let request = Request::post(OAuth2Introspection::PATH)
            .bearer(MockHomeserverConnection::VALID_BEARER_TOKEN)
            .form(json!({ "token": "some_token" }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: IntrospectionResponse = response.json();
        assert!(!response.active);

        // Check with another token, we should get a 401
        let request = Request::post(OAuth2Introspection::PATH)
            .bearer("another_token")
            .form(json!({ "token": "some_token" }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        let response: ClientError = response.json();
        assert_eq!(response.error, ClientErrorCode::AccessDenied);
    }
}
