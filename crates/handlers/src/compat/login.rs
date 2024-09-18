// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{extract::State, response::IntoResponse, Json};
use axum_extra::typed_header::TypedHeader;
use chrono::Duration;
use hyper::StatusCode;
use mas_axum_utils::sentry::SentryEventID;
use mas_config::RestAuthProviderConfig;
use mas_data_model::{
    CompatSession, CompatSsoLoginState, Device, InvalidDeviceID, SiteConfig, TokenType, User,
    UserAgent,
};
use mas_matrix::{BoxHomeserverConnection, ProvisionRequest};
use mas_storage::{
    compat::{
        CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionFilter,
        CompatSessionRepository, CompatSsoLoginRepository,
    },
    user::{UserPasswordRepository, UserRepository},
    BoxClock, BoxRepository, BoxRng, Clock, Pagination, RepositoryAccess,
};
use rand::{CryptoRng, RngCore};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, DurationMilliSeconds};
use thiserror::Error;
use tracing::{error, info};
use zeroize::Zeroizing;

use super::MatrixError;
use crate::{
    impl_from_error_for_route, passwords::PasswordManager, rate_limit::PasswordCheckLimitedError,
    BoundActivityTracker, Limiter, RequesterFingerprint,
};

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum LoginType {
    #[serde(rename = "m.login.password")]
    Password,

    // we will leave MSC3824 `actions` as undefined for this auth type as unclear
    // how it should be interpreted
    #[serde(rename = "m.login.token")]
    Token,

    #[serde(rename = "m.login.sso")]
    Sso {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        identity_providers: Vec<SsoIdentityProvider>,
        #[serde(rename = "org.matrix.msc3824.delegated_oidc_compatibility")]
        delegated_oidc_compatibility: bool,
    },
}

#[derive(Debug, Serialize)]
struct SsoIdentityProvider {
    id: &'static str,
    name: &'static str,
}

#[derive(Debug, Serialize)]
struct LoginTypes {
    flows: Vec<LoginType>,
}

#[derive(Serialize)]
struct AuthRequest {
    user: AuthUser,
}

#[derive(Serialize)]
struct AuthUser {
    id: String,
    password: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    auth: AuthResult,
}

#[derive(Deserialize)]
struct AuthResult {
    success: bool,
}

#[tracing::instrument(name = "handlers.compat.login.get", skip_all)]
pub(crate) async fn get(State(password_manager): State<PasswordManager>) -> impl IntoResponse {
    let flows = if password_manager.is_enabled() {
        vec![
            LoginType::Password,
            LoginType::Sso {
                identity_providers: vec![],
                delegated_oidc_compatibility: true,
            },
            LoginType::Token,
        ]
    } else {
        vec![
            LoginType::Sso {
                identity_providers: vec![],
                delegated_oidc_compatibility: true,
            },
            LoginType::Token,
        ]
    };

    let res = LoginTypes { flows };

    Json(res)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestBody {
    #[serde(flatten)]
    credentials: Credentials,

    #[serde(default)]
    refresh_token: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Credentials {
    #[serde(rename = "m.login.password")]
    Password {
        identifier: Identifier,
        password: String,
    },

    #[serde(rename = "m.login.token")]
    Token { token: String },

    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Identifier {
    #[serde(rename = "m.id.user")]
    User { user: String },

    #[serde(other)]
    Unsupported,
}

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseBody {
    access_token: String,
    device_id: Device,
    user_id: String,
    refresh_token: Option<String>,
    #[serde_as(as = "Option<DurationMilliSeconds<i64>>")]
    expires_in_ms: Option<Duration>,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("unsupported login method")]
    Unsupported,

    #[error("user not found")]
    UserNotFound,

    #[error("session not found")]
    SessionNotFound,

    #[error("user has no password")]
    NoPassword,

    #[error("password verification failed")]
    PasswordVerificationFailed(#[source] anyhow::Error),

    #[error("request rate limited")]
    RateLimited(#[from] PasswordCheckLimitedError),

    #[error("login took too long")]
    LoginTookTooLong,

    #[error("invalid login token")]
    InvalidLoginToken,

    #[error("invalid device ID: {0}")]
    InvalidDeviceID(#[from] InvalidDeviceID),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        let response = match self {
            Self::Internal(_) | Self::SessionNotFound => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Internal server error",
                status: StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::RateLimited(_) => MatrixError {
                errcode: "M_LIMIT_EXCEEDED",
                error: "Too many login attempts",
                status: StatusCode::TOO_MANY_REQUESTS,
            },
            Self::Unsupported => MatrixError {
                errcode: "M_UNRECOGNIZED",
                error: "Invalid login type",
                status: StatusCode::BAD_REQUEST,
            },
            Self::InvalidDeviceID(_) => MatrixError {
                errcode: "M_UNRECOGNIZED",
                error: "Invalid device ID",
                status: StatusCode::BAD_REQUEST,
            },
            Self::UserNotFound | Self::NoPassword | Self::PasswordVerificationFailed(_) => {
                MatrixError {
                    errcode: "M_FORBIDDEN",
                    error: "Invalid username/password",
                    status: StatusCode::FORBIDDEN,
                }
            }
            Self::LoginTookTooLong => MatrixError {
                errcode: "M_FORBIDDEN",
                error: "Login token expired",
                status: StatusCode::FORBIDDEN,
            },
            Self::InvalidLoginToken => MatrixError {
                errcode: "M_FORBIDDEN",
                error: "Invalid login token",
                status: StatusCode::FORBIDDEN,
            },
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

pub async fn authenticate_via_rest_api(
    mxid: String,
    password: String,
    rest_auth_provider: RestAuthProviderConfig,
) -> Result<bool, RouteError> {
    let client = Client::new();
    let auth_url = format!(
        "{}/_matrix-internal/identity/{}/check_credentials",
        rest_auth_provider.url, rest_auth_provider.version
    );

    let request_body = AuthRequest {
        user: AuthUser {
            id: mxid.clone(),
            password,
        },
    };

    info!("Sending authentication request for user: {}", mxid);

    let response = client
        .post(auth_url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to send authentication request: {}", e);
            RouteError::Internal(Box::new(e))
        })?;

    if response.status().is_success() {
        info!("Received successful response for user: {}", mxid);

        let auth_response: AuthResponse = response.json().await.map_err(|e| {
            error!("Failed to parse authentication response: {}", e);
            RouteError::Internal(Box::new(e))
        })?;

        if auth_response.auth.success {
            info!("Authentication successful for user: {}", mxid);
            return Ok(true);
        }
        info!("Authentication failed for user: {}", mxid);
        return Err(RouteError::PasswordVerificationFailed(anyhow::Error::msg(
            "Authentication failed",
        )));
    }

    error!(
        "Authentication request returned an invalid response status for user: {}",
        mxid
    );
    Err(RouteError::PasswordVerificationFailed(anyhow::Error::msg(
        "Invalid response status",
    )))
}

pub async fn start_new_session(
    rng: &mut (impl RngCore + CryptoRng + Send),
    clock: &impl Clock,
    repo: &mut BoxRepository,
    user: User,
    device_id: Option<String>,
) -> Result<(CompatSession, User), RouteError> {
    // Lock the user sync to make sure we don't get into a race condition
    repo.user().acquire_lock_for_sync(&user).await?;

    // Now that the user credentials have been verified, start a new compat session
    let device = if let Some(id) = device_id { Device::try_from(id).map_err(RouteError::InvalidDeviceID)? } else {
        // Generate a new device ID only if not provided
        let device: Device = Device::generate(rng);
        device
    };

    // If an existing session is found, use it
    let filter = CompatSessionFilter::new()
        .for_user(&user)
        .for_device(&device);
    let pagination = Pagination::first(1);
    let existing_sessions = repo.compat_session().list(filter, pagination).await?;

    let session: CompatSession = if existing_sessions.edges.is_empty() {
        repo
            .compat_session()
            .add(rng, clock, &user, device, None, false)
            .await?
    } else {
        let session = &existing_sessions.edges[0].0;
        session.to_owned()
    };

    Ok((session, user))
}

#[tracing::instrument(name = "handlers.compat.login.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(password_manager): State<PasswordManager>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    State(homeserver): State<BoxHomeserverConnection>,
    State(site_config): State<SiteConfig>,
    State(limiter): State<Limiter>,
    requester: RequesterFingerprint,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    Json(input): Json<RequestBody>,
) -> Result<impl IntoResponse, RouteError> {
    let user_agent = user_agent.map(|ua| UserAgent::parse(ua.as_str().to_owned()));
    let (mut session, user) = match (password_manager.is_enabled(), input.credentials) {
        (
            true,
            Credentials::Password {
                identifier: Identifier::User { user: username },
                password,
            },
        ) => {
            let device_id = input.device_id;
            let mxid: String = homeserver.mxid(&username);
            // Check if rest_auth_provider is set
            if let Ok(Some(rest_auth_url)) = password_manager.get_rest_auth_provider() {
                // If rest_auth_provider is enabled, authenticate via REST API
                let authenticated =
                    authenticate_via_rest_api(mxid.clone(), password.clone(), rest_auth_url)
                        .await?;
                if authenticated {
                    let user = repo
                        .user()
                        .find_by_username(&username)
                        .await?
                        .filter(mas_data_model::User::is_valid);

                    let user = if let Some(user) = user {
                        // User found : proceed
                        user
                    } else {
                        // User not found while existing in the provider: create it
                        let new_user =
                            repo.user().add(&mut rng, &clock, username.clone()).await?;

                        // Replicate in Synapse
                        homeserver
                            .provision_user(&ProvisionRequest::new(
                                mxid.clone(),
                                username.clone(),
                            ))
                            .await
                            .unwrap();

                        new_user
                    };
                    // Update the password if needed
                    let result = password_manager
                        .hash(&mut rng, password.into_bytes().into())
                        .await;
                    let (version, hashed_password) = match result {
                        Ok((version, hashed_password)) => (version, hashed_password),
                        Err(err) => return Err(RouteError::Internal(err.into())),
                    };
                    repo.user_password()
                        .upsert(&mut rng, &clock, &user, version, hashed_password)
                        .await?;

                    // Start a new compat session without verifying the password again
                    start_new_session(&mut rng, &clock, &mut repo, user, device_id).await?
                } else {
                    return Err(RouteError::PasswordVerificationFailed(anyhow::Error::msg(
                        "Authentication failed via REST API",
                    )));
                }
            } else {
                // If rest_auth_provider is not enabled, proceed with the normal authentication
                let user = user_login_with_password(
                    &mut rng,
                    &clock,
                    &password_manager,
                    &limiter,
                    requester,
                    &mut repo,
                    username,
                    password,
                )
                .await?;
                start_new_session(&mut rng, &clock, &mut repo, user, device_id).await?
            }
        }

        (_, Credentials::Token { token }) => token_login(&mut repo, &clock, &token).await?,

        _ => {
            return Err(RouteError::Unsupported);
        }
    };

    if let Some(user_agent) = user_agent {
        session = repo
            .compat_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let user_id = homeserver.mxid(&user.username);

    // If the client asked for a refreshable token, make it expire
    let expires_in = if input.refresh_token {
        Some(site_config.compat_token_ttl)
    } else {
        None
    };

    let access_token = TokenType::CompatAccessToken.generate(&mut rng);
    let access_token = repo
        .compat_access_token()
        .add(&mut rng, &clock, &session, access_token, expires_in)
        .await?;

    let refresh_token = if input.refresh_token {
        let refresh_token = TokenType::CompatRefreshToken.generate(&mut rng);
        let refresh_token = repo
            .compat_refresh_token()
            .add(&mut rng, &clock, &session, &access_token, refresh_token)
            .await?;
        Some(refresh_token.token)
    } else {
        None
    };

    repo.save().await?;
    info!(
        "Session and tokens saved successfully for user: {}",
        user.username
    );

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    Ok(Json(ResponseBody {
        access_token: access_token.token,
        device_id: session.device,
        user_id,
        refresh_token,
        expires_in_ms: expires_in,
    }))
}

async fn token_login(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    token: &str,
) -> Result<(CompatSession, User), RouteError> {
    let login = repo
        .compat_sso_login()
        .find_by_token(token)
        .await?
        .ok_or(RouteError::InvalidLoginToken)?;

    let now = clock.now();
    let session_id = match login.state {
        CompatSsoLoginState::Pending => {
            tracing::error!(
                compat_sso_login.id = %login.id,
                "Exchanged a token for a login that was not fullfilled yet"
            );
            return Err(RouteError::InvalidLoginToken);
        }
        CompatSsoLoginState::Fulfilled {
            fulfilled_at,
            session_id,
            ..
        } => {
            if now > fulfilled_at + Duration::microseconds(30 * 1000 * 1000) {
                return Err(RouteError::LoginTookTooLong);
            }

            session_id
        }
        CompatSsoLoginState::Exchanged {
            exchanged_at,
            session_id,
            ..
        } => {
            if now > exchanged_at + Duration::microseconds(30 * 1000 * 1000) {
                // TODO: log that session out
                tracing::error!(
                    compat_sso_login.id = %login.id,
                    compat_session.id = %session_id,
                    "Login token exchanged a second time more than 30s after"
                );
            }

            return Err(RouteError::InvalidLoginToken);
        }
    };

    let session = repo
        .compat_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    let user = repo
        .user()
        .lookup(session.user_id)
        .await?
        .filter(mas_data_model::User::is_valid)
        .ok_or(RouteError::UserNotFound)?;

    repo.compat_sso_login().exchange(clock, login).await?;

    Ok((session, user))
}

pub async fn user_login_with_password(
    mut rng: &mut (impl RngCore + CryptoRng + Send),
    clock: &impl Clock,
    password_manager: &PasswordManager,
    limiter: &Limiter,
    requester: RequesterFingerprint,
    repo: &mut BoxRepository,
    username: String,
    password: String,
) -> Result<User, RouteError> {
    // Find the user
    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .filter(mas_data_model::User::is_valid)
        .ok_or(RouteError::UserNotFound)?;

    // Check the rate limit
    limiter.check_password(requester, &user).map_err(|e| {
        tracing::warn!(error = &e as &dyn std::error::Error);
        RouteError::RateLimited(e)
    })?;

    // Lookup its password
    let user_password = repo
        .user_password()
        .active(&user)
        .await?
        .ok_or(RouteError::NoPassword)?;

    // Verify the password
    let password = Zeroizing::new(password.into_bytes());

    let new_password_hash = password_manager
        .verify_and_upgrade(
            &mut rng,
            user_password.version,
            password,
            user_password.hashed_password.clone(),
        )
        .await
        .map_err(RouteError::PasswordVerificationFailed)?;

    if let Some((version, hashed_password)) = new_password_hash {
        // Save the upgraded password if needed
        repo.user_password()
            .add(
                &mut rng,
                clock,
                &user,
                version,
                hashed_password,
                Some(&user_password),
            )
            .await?;
    }

    Ok(user)
}

#[cfg(test)]
mod tests {
    use hyper::Request;
    use mas_matrix::{HomeserverConnection, ProvisionRequest};
    use mockito::{Matcher, Server};
    use rand::distributions::{Alphanumeric, DistString};
    use serde_json::json;
    use sqlx::PgPool;

    use super::*;
    use crate::test_utils::{setup, RequestBuilderExt, ResponseExt, TestState};

    /// Test that the server advertises the right login flows.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Now let's get the login flows
        let request = Request::get("/_matrix/client/v3/login").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body,
            serde_json::json!({
                "flows": [
                    {
                        "type": "m.login.password",
                    },
                    {
                        "type": "m.login.sso",
                        "org.matrix.msc3824.delegated_oidc_compatibility": true,
                    },
                    {
                        "type": "m.login.token",
                    }
                ],
            })
        );
    }

    /// Test that the server doesn't allow login with a password if the password
    /// manager is disabled
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_disabled(pool: PgPool) {
        setup();
        let state = {
            let mut state = TestState::from_pool(pool).await.unwrap();
            state.password_manager = PasswordManager::disabled();
            state
        };

        // Now let's get the login flows
        let request = Request::get("/_matrix/client/v3/login").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body,
            serde_json::json!({
                "flows": [
                    {
                        "type": "m.login.sso",
                        "org.matrix.msc3824.delegated_oidc_compatibility": true,
                    },
                    {
                        "type": "m.login.token",
                    }
                ],
            })
        );

        // Try to login with a password, it should be rejected
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_UNRECOGNIZED");
    }

    /// Test that a user can login with a password using the Matrix
    /// compatibility API.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_user_login_with_password(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Let's provision a user and add a password to it. This part is hard to test
        // with just HTTP requests, so we'll use the repository directly.
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let mxid = state.homeserver_connection.mxid(&user.username);
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(mxid, &user.sub))
            .await
            .unwrap();

        let (version, hashed_password) = state
            .password_manager
            .hash(
                &mut state.rng(),
                Zeroizing::new("password".to_owned().into_bytes()),
            )
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

        // Now let's try to login with the password, without asking for a refresh token.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: ResponseBody = response.json();
        assert!(!body.access_token.is_empty());
        assert_eq!(body.device_id.as_str().len(), 10);
        assert_eq!(body.user_id, "@alice:example.com");
        assert_eq!(body.refresh_token, None);
        assert_eq!(body.expires_in_ms, None);

        // Do the same, but this time ask for a refresh token.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
            "refresh_token": true,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: ResponseBody = response.json();
        assert!(!body.access_token.is_empty());
        assert_eq!(body.device_id.as_str().len(), 10);
        assert_eq!(body.user_id, "@alice:example.com");
        assert!(body.refresh_token.is_some());
        assert!(body.expires_in_ms.is_some());

        // Try to login with a wrong password.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "wrongpassword",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_FORBIDDEN");

        // Try to login with a wrong username.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "bob",
            },
            "password": "wrongpassword",
        }));

        let old_body = body;
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();

        // The response should be the same as the previous one, so that we don't leak if
        // it's the user that is invalid or the password.
        assert_eq!(body, old_body);
    }

    #[tokio::test]
    async fn test_authenticate_via_rest_api_success() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("POST", "/_matrix-internal/identity/v2/check_credentials")
            .match_body(Matcher::PartialJson(json!({
                "user": {
                    "id": "@alice:example.com",
                    "password": "password123"
                }
            })))
            .with_status(200)
            .with_body(
                json!({
                    "auth": {
                        "success": true
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let rest_auth_provider = RestAuthProviderConfig::new(server.url(), "v2".to_owned());
        let result = authenticate_via_rest_api(
            "@alice:example.com".to_owned(),
            "password123".to_owned(),
            rest_auth_provider,
        )
        .await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_authenticate_via_rest_api_failure() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("POST", "/_matrix-internal/identity/v2/check_credentials")
            .match_body(Matcher::PartialJson(json!({
                "user": {
                    "id": "@alice:example.com",
                    "password": "wrongpassword"
                }
            })))
            .with_status(200)
            .with_body(
                json!({
                    "auth": {
                        "success": false
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let rest_auth_provider = RestAuthProviderConfig::new(server.url(), "v2".to_owned());
        let result = authenticate_via_rest_api(
            "@alice:example.com".to_owned(),
            "wrongpassword".to_owned(),
            rest_auth_provider,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_via_rest_api_invalid_status() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("POST", "/_matrix-internal/identity/v2/check_credentials")
            .with_status(500)
            .create_async()
            .await;

        let rest_auth_provider = RestAuthProviderConfig::new(server.url(), "v2".to_owned());
        let result = authenticate_via_rest_api(
            "@alice:example.com".to_owned(),
            "password123".to_owned(),
            rest_auth_provider,
        )
        .await;

        assert!(result.is_err());
    }

    /// Test that password logins are rate limited.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_rate_limit(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Let's provision a user without a password. This should be enough to trigger
        // the rate limit.
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let mxid = state.homeserver_connection.mxid(&user.username);
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(mxid, &user.sub))
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now let's try to login with the password, without asking for a refresh token.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));

        // First three attempts should just tell about the invalid credentials
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::FORBIDDEN);

        // The fourth attempt should be rate limited
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::TOO_MANY_REQUESTS);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED");
        assert_eq!(body["error"], "Too many login attempts");
    }

    /// Test the response of an unsupported login flow.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unsupported_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Try to login with an unsupported login flow.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.unsupported",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_UNRECOGNIZED");
    }

    /// Test `m.login.token` login flow.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_token_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a user
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let mxid = state.homeserver_connection.mxid(&user.username);
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(mxid, &user.sub))
            .await
            .unwrap();

        // First try with an invalid token
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": "someinvalidtoken",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_FORBIDDEN");

        let (device, token) = get_login_token(&state, &user).await;

        // Try to login with the token.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": token,
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: ResponseBody = response.json();
        assert!(!body.access_token.is_empty());
        assert_eq!(body.device_id, device);
        assert_eq!(body.user_id, "@alice:example.com");
        assert_eq!(body.refresh_token, None);
        assert_eq!(body.expires_in_ms, None);

        // Try again with the same token, it should fail.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": token,
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_FORBIDDEN");

        // Try to login, but wait too long before sending the request.
        let (_device, token) = get_login_token(&state, &user).await;

        // Advance the clock to make the token expire.
        state
            .clock
            .advance(Duration::microseconds(60 * 1000 * 1000));

        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": token,
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["errcode"], "M_FORBIDDEN");
    }

    /// Get a login token for a user.
    /// Returns the device and the token.
    ///
    /// # Panics
    ///
    /// Panics if the repository fails.
    async fn get_login_token(state: &TestState, user: &User) -> (Device, String) {
        // XXX: This is a bit manual, but this is what basically the SSO login flow
        // does.
        let mut repo = state.repository().await.unwrap();

        // Generate a device and a token randomly
        let token = Alphanumeric.sample_string(&mut state.rng(), 32);
        let device = Device::generate(&mut state.rng());

        // Start a compat SSO login flow
        let login = repo
            .compat_sso_login()
            .add(
                &mut state.rng(),
                &state.clock,
                token.clone(),
                "http://example.com/".parse().unwrap(),
            )
            .await
            .unwrap();

        // Complete the flow by fulfilling it with a session
        let compat_session = repo
            .compat_session()
            .add(
                &mut state.rng(),
                &state.clock,
                user,
                device.clone(),
                None,
                false,
            )
            .await
            .unwrap();

        repo.compat_sso_login()
            .fulfill(&state.clock, login, &compat_session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        (device, token)
    }
}
