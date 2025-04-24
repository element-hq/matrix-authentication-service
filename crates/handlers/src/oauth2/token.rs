// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::sync::{Arc, LazyLock};

use axum::{Json, extract::State, response::IntoResponse};
use axum_extra::typed_header::TypedHeader;
use chrono::Duration;
use headers::{CacheControl, HeaderMap, HeaderMapExt, Pragma};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    record_error,
};
use mas_data_model::{
    AuthorizationGrantStage, Client, Device, DeviceCodeGrantState, SiteConfig, TokenType,
};
use mas_keystore::{Encrypter, Keystore};
use mas_matrix::HomeserverConnection;
use mas_oidc_client::types::scope::ScopeToken;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{
    BoxClock, BoxRepository, BoxRng, Clock, RepositoryAccess,
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository,
        OAuth2RefreshTokenRepository, OAuth2SessionRepository,
    },
    user::BrowserSessionRepository,
};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce::CodeChallengeError,
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, ClientCredentialsGrant,
        DeviceCodeGrant, GrantType, RefreshTokenGrant,
    },
    scope,
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use thiserror::Error;
use tracing::{debug, info, warn};
use ulid::Ulid;

use super::{generate_id_token, generate_token_pair};
use crate::{BoundActivityTracker, METER, impl_from_error_for_route};

static TOKEN_REQUEST_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.oauth2.token_request")
        .with_description("How many OAuth 2.0 token requests have gone through")
        .with_unit("{request}")
        .build()
});
const GRANT_TYPE: Key = Key::from_static_str("grant_type");
const RESULT: Key = Key::from_static_str("successful");

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bad request")]
    BadRequest,

    #[error("pkce verification failed")]
    PkceVerification(#[from] CodeChallengeError),

    #[error("client not found")]
    ClientNotFound,

    #[error("client not allowed to use the token endpoint: {0}")]
    ClientNotAllowed(Ulid),

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

    #[error("grant not found")]
    GrantNotFound,

    #[error("invalid grant {0}")]
    InvalidGrant(Ulid),

    #[error("refresh token not found")]
    RefreshTokenNotFound,

    #[error("refresh token {0} is invalid")]
    RefreshTokenInvalid(Ulid),

    #[error("session {0} is invalid")]
    SessionInvalid(Ulid),

    #[error("client id mismatch: expected {expected}, got {actual}")]
    ClientIDMismatch { expected: Ulid, actual: Ulid },

    #[error("policy denied the request: {0}")]
    DeniedByPolicy(mas_policy::EvaluationResult),

    #[error("unsupported grant type")]
    UnsupportedGrantType,

    #[error("client {0} is not authorized to use this grant type")]
    UnauthorizedClient(Ulid),

    #[error("unexpected client {was} (expected {expected})")]
    UnexptectedClient { was: Ulid, expected: Ulid },

    #[error("failed to load browser session {0}")]
    NoSuchBrowserSession(Ulid),

    #[error("failed to load oauth session {0}")]
    NoSuchOAuthSession(Ulid),

    #[error(
        "failed to load the next refresh token ({next:?}) from the previous one ({previous:?})"
    )]
    NoSuchNextRefreshToken { next: Ulid, previous: Ulid },

    #[error(
        "failed to load the access token ({access_token:?}) associated with the next refresh token ({refresh_token:?})"
    )]
    NoSuchNextAccessToken {
        access_token: Ulid,
        refresh_token: Ulid,
    },

    #[error("no access token associated with the refresh token {refresh_token:?}")]
    NoAccessTokenOnRefreshToken { refresh_token: Ulid },

    #[error("device code grant expired")]
    DeviceCodeExpired,

    #[error("device code grant is still pending")]
    DeviceCodePending,

    #[error("device code grant was rejected")]
    DeviceCodeRejected,

    #[error("device code grant was already exchanged")]
    DeviceCodeExchanged,

    #[error("failed to provision device")]
    ProvisionDeviceFailed(#[source] anyhow::Error),
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(
            self,
            Self::Internal(_)
                | Self::ClientCredentialsVerification { .. }
                | Self::NoSuchBrowserSession(_)
                | Self::NoSuchOAuthSession(_)
                | Self::ProvisionDeviceFailed(_)
                | Self::NoSuchNextRefreshToken { .. }
                | Self::NoSuchNextAccessToken { .. }
                | Self::NoAccessTokenOnRefreshToken { .. }
        );

        TOKEN_REQUEST_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);

        let response = match self {
            Self::Internal(_)
            | Self::ClientCredentialsVerification { .. }
            | Self::NoSuchBrowserSession(_)
            | Self::NoSuchOAuthSession(_)
            | Self::ProvisionDeviceFailed(_)
            | Self::NoSuchNextRefreshToken { .. }
            | Self::NoSuchNextAccessToken { .. }
            | Self::NoAccessTokenOnRefreshToken { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            ),

            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            ),

            Self::PkceVerification(err) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidGrant)
                        .with_description(format!("PKCE verification failed: {err}")),
                ),
            ),

            Self::ClientNotFound | Self::InvalidClientCredentials { .. } => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            ),

            Self::ClientNotAllowed(_)
            | Self::UnauthorizedClient(_)
            | Self::UnexptectedClient { .. } => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::UnauthorizedClient)),
            ),

            Self::DeniedByPolicy(evaluation) => (
                StatusCode::FORBIDDEN,
                Json(
                    ClientError::from(ClientErrorCode::InvalidScope).with_description(
                        evaluation
                            .violations
                            .into_iter()
                            .map(|violation| violation.msg)
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                ),
            ),

            Self::DeviceCodeRejected => (
                StatusCode::FORBIDDEN,
                Json(ClientError::from(ClientErrorCode::AccessDenied)),
            ),

            Self::DeviceCodeExpired => (
                StatusCode::FORBIDDEN,
                Json(ClientError::from(ClientErrorCode::ExpiredToken)),
            ),

            Self::DeviceCodePending => (
                StatusCode::FORBIDDEN,
                Json(ClientError::from(ClientErrorCode::AuthorizationPending)),
            ),

            Self::InvalidGrant(_)
            | Self::DeviceCodeExchanged
            | Self::RefreshTokenNotFound
            | Self::RefreshTokenInvalid(_)
            | Self::SessionInvalid(_)
            | Self::ClientIDMismatch { .. }
            | Self::GrantNotFound => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidGrant)),
            ),

            Self::UnsupportedGrantType => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::UnsupportedGrantType)),
            ),
        };

        (sentry_event_id, response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(super::IdTokenSignatureError);

#[tracing::instrument(
    name = "handlers.oauth2.token.post",
    fields(client.id = client_authorization.client_id()),
    skip_all,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(http_client): State<reqwest::Client>,
    State(key_store): State<Keystore>,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    State(site_config): State<SiteConfig>,
    State(encrypter): State<Encrypter>,
    policy: Policy,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    client_authorization: ClientAuthorization<AccessTokenRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed(client.id))?;

    client_authorization
        .credentials
        .verify(&http_client, &encrypter, method, &client)
        .await
        .map_err(|err| {
            // Classify the error differntly, depending on whether it's an 'internal' error,
            // or just because the client presented invalid credentials.
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

    let form = client_authorization.form.ok_or(RouteError::BadRequest)?;

    let grant_type = form.grant_type();

    let (reply, repo) = match form {
        AccessTokenRequest::AuthorizationCode(grant) => {
            authorization_code_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &key_store,
                &url_builder,
                &site_config,
                repo,
                &homeserver,
                user_agent,
            )
            .await?
        }
        AccessTokenRequest::RefreshToken(grant) => {
            refresh_token_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &site_config,
                repo,
                user_agent,
            )
            .await?
        }
        AccessTokenRequest::ClientCredentials(grant) => {
            client_credentials_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &site_config,
                repo,
                policy,
                user_agent,
            )
            .await?
        }
        AccessTokenRequest::DeviceCode(grant) => {
            device_code_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &key_store,
                &url_builder,
                &site_config,
                repo,
                &homeserver,
                user_agent,
            )
            .await?
        }
        _ => {
            return Err(RouteError::UnsupportedGrantType);
        }
    };

    repo.save().await?;

    TOKEN_REQUEST_COUNTER.add(
        1,
        &[
            KeyValue::new(GRANT_TYPE, grant_type),
            KeyValue::new(RESULT, "success"),
        ],
    );

    let mut headers = HeaderMap::new();
    headers.typed_insert(CacheControl::new().with_no_store());
    headers.typed_insert(Pragma::no_cache());

    Ok((headers, Json(reply)))
}

#[allow(clippy::too_many_lines)] // TODO: refactor some parts out
async fn authorization_code_grant(
    mut rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &AuthorizationCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    homeserver: &Arc<dyn HomeserverConnection>,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(RouteError::UnauthorizedClient(client.id));
    }

    let authz_grant = repo
        .oauth2_authorization_grant()
        .find_by_code(&grant.code)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    let now = clock.now();

    let session_id = match authz_grant.stage {
        AuthorizationGrantStage::Cancelled { cancelled_at } => {
            debug!(%cancelled_at, "Authorization grant was cancelled");
            return Err(RouteError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Exchanged {
            exchanged_at,
            fulfilled_at,
            session_id,
        } => {
            warn!(%exchanged_at, %fulfilled_at, "Authorization code was already exchanged");

            // Ending the session if the token was already exchanged more than 20s ago
            if now - exchanged_at > Duration::microseconds(20 * 1000 * 1000) {
                warn!(oauth_session.id = %session_id, "Ending potentially compromised session");
                let session = repo
                    .oauth2_session()
                    .lookup(session_id)
                    .await?
                    .ok_or(RouteError::NoSuchOAuthSession(session_id))?;

                //if !session.is_finished() {
                repo.oauth2_session().finish(clock, session).await?;
                repo.save().await?;
                //}
            }

            return Err(RouteError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Pending => {
            warn!("Authorization grant has not been fulfilled yet");
            return Err(RouteError::InvalidGrant(authz_grant.id));
        }
        AuthorizationGrantStage::Fulfilled {
            session_id,
            fulfilled_at,
        } => {
            if now - fulfilled_at > Duration::microseconds(10 * 60 * 1000 * 1000) {
                warn!("Code exchange took more than 10 minutes");
                return Err(RouteError::InvalidGrant(authz_grant.id));
            }

            session_id
        }
    };

    let mut session = repo
        .oauth2_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::NoSuchOAuthSession(session_id))?;

    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    // This should never happen, since we looked up in the database using the code
    let code = authz_grant
        .code
        .as_ref()
        .ok_or(RouteError::InvalidGrant(authz_grant.id))?;

    if client.id != session.client_id {
        return Err(RouteError::UnexptectedClient {
            was: client.id,
            expected: session.client_id,
        });
    }

    match (code.pkce.as_ref(), grant.code_verifier.as_ref()) {
        (None, None) => {}
        // We have a challenge but no verifier (or vice-versa)? Bad request.
        (Some(_), None) | (None, Some(_)) => return Err(RouteError::BadRequest),
        // If we have both, we need to check the code validity
        (Some(pkce), Some(verifier)) => {
            pkce.verify(verifier)?;
        }
    }

    let Some(user_session_id) = session.user_session_id else {
        tracing::warn!("No user session associated with this OAuth2 session");
        return Err(RouteError::InvalidGrant(authz_grant.id));
    };

    let browser_session = repo
        .browser_session()
        .lookup(user_session_id)
        .await?
        .ok_or(RouteError::NoSuchBrowserSession(user_session_id))?;

    let last_authentication = repo
        .browser_session()
        .get_last_authentication(&browser_session)
        .await?;

    let ttl = site_config.access_token_ttl;
    let (access_token, refresh_token) =
        generate_token_pair(&mut rng, clock, &mut repo, &session, ttl).await?;

    let id_token = if session.scope.contains(&scope::OPENID) {
        Some(generate_id_token(
            &mut rng,
            clock,
            url_builder,
            key_store,
            client,
            Some(&authz_grant),
            &browser_session,
            Some(&access_token),
            last_authentication.as_ref(),
        )?)
    } else {
        None
    };

    let mut params = AccessTokenResponse::new(access_token.access_token)
        .with_expires_in(ttl)
        .with_refresh_token(refresh_token.refresh_token)
        .with_scope(session.scope.clone());

    if let Some(id_token) = id_token {
        params = params.with_id_token(id_token);
    }

    // Lock the user sync to make sure we don't get into a race condition
    repo.user()
        .acquire_lock_for_sync(&browser_session.user)
        .await?;

    // Look for device to provision
    let mxid = homeserver.mxid(&browser_session.user.username);
    for scope in &*session.scope {
        if let Some(device) = Device::from_scope_token(scope) {
            homeserver
                .create_device(&mxid, device.as_str())
                .await
                .map_err(RouteError::ProvisionDeviceFailed)?;
        }
    }

    repo.oauth2_authorization_grant()
        .exchange(clock, authz_grant)
        .await?;

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    Ok((params, repo))
}

#[allow(clippy::too_many_lines)]
async fn refresh_token_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &RefreshTokenGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::RefreshToken) {
        return Err(RouteError::UnauthorizedClient(client.id));
    }

    let refresh_token = repo
        .oauth2_refresh_token()
        .find_by_token(&grant.refresh_token)
        .await?
        .ok_or(RouteError::RefreshTokenNotFound)?;

    let mut session = repo
        .oauth2_session()
        .lookup(refresh_token.session_id)
        .await?
        .ok_or(RouteError::NoSuchOAuthSession(refresh_token.session_id))?;

    // Let's for now record the user agent on each refresh, that should be
    // responsive enough and not too much of a burden on the database.
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    if !session.is_valid() {
        return Err(RouteError::SessionInvalid(session.id));
    }

    if client.id != session.client_id {
        // As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
        return Err(RouteError::ClientIDMismatch {
            expected: session.client_id,
            actual: client.id,
        });
    }

    if !refresh_token.is_valid() {
        // We're seing a refresh token that already has been consumed, this might be a
        // double-refresh or a replay attack

        // First, get the next refresh token
        let Some(next_refresh_token_id) = refresh_token.next_refresh_token_id() else {
            // If we don't have a 'next' refresh token, it may just be because this was
            // before we were recording those. Let's just treat it as a replay.
            return Err(RouteError::RefreshTokenInvalid(refresh_token.id));
        };

        let Some(next_refresh_token) = repo
            .oauth2_refresh_token()
            .lookup(next_refresh_token_id)
            .await?
        else {
            return Err(RouteError::NoSuchNextRefreshToken {
                next: next_refresh_token_id,
                previous: refresh_token.id,
            });
        };

        // Check if the next refresh token was already consumed or not
        if !next_refresh_token.is_valid() {
            // XXX: This is a replay, we *may* want to invalidate the session
            return Err(RouteError::RefreshTokenInvalid(next_refresh_token.id));
        }

        // Check if the associated access token was already used
        let Some(access_token_id) = next_refresh_token.access_token_id else {
            // This should in theory not happen: this means an access token got cleaned up,
            // but the refresh token was still valid.
            return Err(RouteError::NoAccessTokenOnRefreshToken {
                refresh_token: next_refresh_token.id,
            });
        };

        // Load it
        let next_access_token = repo
            .oauth2_access_token()
            .lookup(access_token_id)
            .await?
            .ok_or(RouteError::NoSuchNextAccessToken {
                access_token: access_token_id,
                refresh_token: next_refresh_token_id,
            })?;

        if next_access_token.is_used() {
            // XXX: This is a replay, we *may* want to invalidate the session
            return Err(RouteError::RefreshTokenInvalid(next_refresh_token.id));
        }

        // Looks like it's a double-refresh, client lost their refresh token on
        // the way back. Let's revoke the unused access and refresh tokens, and
        // issue new ones
        info!(
            oauth2_session.id = %session.id,
            oauth2_client.id = %client.id,
            %refresh_token.id,
            "Refresh token already used, but issued refresh and access tokens are unused. Assuming those were lost; revoking those and reissuing new ones."
        );

        repo.oauth2_access_token()
            .revoke(clock, next_access_token)
            .await?;

        repo.oauth2_refresh_token()
            .revoke(clock, next_refresh_token)
            .await?;
    }

    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    let ttl = site_config.access_token_ttl;
    let (new_access_token, new_refresh_token) =
        generate_token_pair(rng, clock, &mut repo, &session, ttl).await?;

    let refresh_token = repo
        .oauth2_refresh_token()
        .consume(clock, refresh_token, &new_refresh_token)
        .await?;

    if let Some(access_token_id) = refresh_token.access_token_id {
        let access_token = repo.oauth2_access_token().lookup(access_token_id).await?;
        if let Some(access_token) = access_token {
            // If it is a double-refresh, it might already be revoked
            if !access_token.state.is_revoked() {
                repo.oauth2_access_token()
                    .revoke(clock, access_token)
                    .await?;
            }
        }
    }

    let params = AccessTokenResponse::new(new_access_token.access_token)
        .with_expires_in(ttl)
        .with_refresh_token(new_refresh_token.refresh_token)
        .with_scope(session.scope);

    Ok((params, repo))
}

async fn client_credentials_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &ClientCredentialsGrant,
    client: &Client,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    mut policy: Policy,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        return Err(RouteError::UnauthorizedClient(client.id));
    }

    // Default to an empty scope if none is provided
    let scope = grant
        .scope
        .clone()
        .unwrap_or_else(|| std::iter::empty::<ScopeToken>().collect());

    // Make the request go through the policy engine
    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            user: None,
            client,
            scope: &scope,
            grant_type: mas_policy::GrantType::ClientCredentials,
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent: user_agent.clone(),
            },
        })
        .await?;
    if !res.valid() {
        return Err(RouteError::DeniedByPolicy(res));
    }

    // Start the session
    let mut session = repo
        .oauth2_session()
        .add_from_client_credentials(rng, clock, client, scope)
        .await?;

    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let ttl = site_config.access_token_ttl;
    let access_token_str = TokenType::AccessToken.generate(rng);

    let access_token = repo
        .oauth2_access_token()
        .add(rng, clock, &session, access_token_str, Some(ttl))
        .await?;

    let mut params = AccessTokenResponse::new(access_token.access_token).with_expires_in(ttl);

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    if !session.scope.is_empty() {
        // We only return the scope if it's not empty
        params = params.with_scope(session.scope);
    }

    Ok((params, repo))
}

async fn device_code_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &DeviceCodeGrant,
    client: &Client,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    site_config: &SiteConfig,
    mut repo: BoxRepository,
    homeserver: &Arc<dyn HomeserverConnection>,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // Check that the client is allowed to use this grant type
    if !client.grant_types.contains(&GrantType::DeviceCode) {
        return Err(RouteError::UnauthorizedClient(client.id));
    }

    let grant = repo
        .oauth2_device_code_grant()
        .find_by_device_code(&grant.device_code)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    // Check that the client match
    if client.id != grant.client_id {
        return Err(RouteError::ClientIDMismatch {
            expected: grant.client_id,
            actual: client.id,
        });
    }

    if grant.expires_at < clock.now() {
        return Err(RouteError::DeviceCodeExpired);
    }

    let browser_session_id = match &grant.state {
        DeviceCodeGrantState::Pending => {
            return Err(RouteError::DeviceCodePending);
        }
        DeviceCodeGrantState::Rejected { .. } => {
            return Err(RouteError::DeviceCodeRejected);
        }
        DeviceCodeGrantState::Exchanged { .. } => {
            return Err(RouteError::DeviceCodeExchanged);
        }
        DeviceCodeGrantState::Fulfilled {
            browser_session_id, ..
        } => *browser_session_id,
    };

    let browser_session = repo
        .browser_session()
        .lookup(browser_session_id)
        .await?
        .ok_or(RouteError::NoSuchBrowserSession(browser_session_id))?;

    // Start the session
    let mut session = repo
        .oauth2_session()
        .add_from_browser_session(rng, clock, client, &browser_session, grant.scope.clone())
        .await?;

    repo.oauth2_device_code_grant()
        .exchange(clock, grant, &session)
        .await?;

    // XXX: should we get the user agent from the device code grant instead?
    if let Some(user_agent) = user_agent {
        session = repo
            .oauth2_session()
            .record_user_agent(session, user_agent)
            .await?;
    }

    let ttl = site_config.access_token_ttl;
    let access_token_str = TokenType::AccessToken.generate(rng);

    let access_token = repo
        .oauth2_access_token()
        .add(rng, clock, &session, access_token_str, Some(ttl))
        .await?;

    let mut params =
        AccessTokenResponse::new(access_token.access_token.clone()).with_expires_in(ttl);

    // If the client uses the refresh token grant type, we also generate a refresh
    // token
    if client.grant_types.contains(&GrantType::RefreshToken) {
        let refresh_token_str = TokenType::RefreshToken.generate(rng);

        let refresh_token = repo
            .oauth2_refresh_token()
            .add(rng, clock, &session, &access_token, refresh_token_str)
            .await?;

        params = params.with_refresh_token(refresh_token.refresh_token);
    }

    // If the client asked for an ID token, we generate one
    if session.scope.contains(&scope::OPENID) {
        let id_token = generate_id_token(
            rng,
            clock,
            url_builder,
            key_store,
            client,
            None,
            &browser_session,
            Some(&access_token),
            None,
        )?;

        params = params.with_id_token(id_token);
    }

    // Lock the user sync to make sure we don't get into a race condition
    repo.user()
        .acquire_lock_for_sync(&browser_session.user)
        .await?;

    // Look for device to provision
    let mxid = homeserver.mxid(&browser_session.user.username);
    for scope in &*session.scope {
        if let Some(device) = Device::from_scope_token(scope) {
            homeserver
                .create_device(&mxid, device.as_str())
                .await
                .map_err(RouteError::ProvisionDeviceFailed)?;
        }
    }

    // XXX: there is a potential (but unlikely) race here, where the activity for
    // the session is recorded before the transaction is committed. We would have to
    // save the repository here to fix that.
    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    if !session.scope.is_empty() {
        // We only return the scope if it's not empty
        params = params.with_scope(session.scope);
    }

    Ok((params, repo))
}

#[cfg(test)]
mod tests {
    use hyper::Request;
    use mas_data_model::{AccessToken, AuthorizationCode, RefreshToken};
    use mas_router::SimpleRoute;
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        requests::{DeviceAuthorizationResponse, ResponseMode},
        scope::{OPENID, Scope},
    };
    use sqlx::PgPool;

    use super::*;
    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_auth_code_grant(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

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

        // Start a grant
        let code = "thisisaverysecurecode";
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                &client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: code.to_owned(),
                    pkce: None,
                }),
                Some("state".to_owned()),
                Some("nonce".to_owned()),
                ResponseMode::Query,
                false,
                None,
            )
            .await
            .unwrap();

        let session = repo
            .oauth2_session()
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                grant.scope.clone(),
            )
            .await
            .unwrap();

        // And fulfill it
        let grant = repo
            .oauth2_authorization_grant()
            .fulfill(&state.clock, &session, grant)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now call the token endpoint to get an access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let AccessTokenResponse { access_token, .. } = response.json();

        // Check that the token is valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Exchange it again, this it should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let error: ClientError = response.json();
        assert_eq!(error.error, ClientErrorCode::InvalidGrant);

        // The token should still be valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Now wait a bit
        state.clock.advance(Duration::try_minutes(1).unwrap());

        // Exchange it again, this it should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let error: ClientError = response.json();
        assert_eq!(error.error, ClientErrorCode::InvalidGrant);

        // And it should have revoked the token we got
        assert!(!state.is_access_token_valid(&access_token).await);

        // Try another one and wait for too long before exchanging it
        let mut repo = state.repository().await.unwrap();
        let code = "thisisanothercode";
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                &client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: code.to_owned(),
                    pkce: None,
                }),
                Some("state".to_owned()),
                Some("nonce".to_owned()),
                ResponseMode::Query,
                false,
                None,
            )
            .await
            .unwrap();

        let session = repo
            .oauth2_session()
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                grant.scope.clone(),
            )
            .await
            .unwrap();

        // And fulfill it
        let grant = repo
            .oauth2_authorization_grant()
            .fulfill(&state.clock, &session, grant)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now wait a bit
        state
            .clock
            .advance(Duration::microseconds(15 * 60 * 1000 * 1000));

        // Exchange it, it should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": grant.redirect_uri,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::InvalidGrant);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_refresh_token_grant(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

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

        // Get a token pair
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

        // First check that the token is valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Now call the token endpoint to get an access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let old_access_token = access_token;
        let old_refresh_token = refresh_token;
        let response: AccessTokenResponse = response.json();
        let access_token = response.access_token;
        let refresh_token = response.refresh_token.expect("to have a refresh token");

        // Check that the new token is valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Check that the old token is no longer valid
        assert!(!state.is_access_token_valid(&old_access_token).await);

        // Call it again with the old token, it should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": old_refresh_token,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::InvalidGrant);

        // Call it again with the new token, it should work
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let _: AccessTokenResponse = response.json();
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_double_refresh(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

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

        // Get a token pair
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

        // First check that the token is valid
        assert!(state.is_access_token_valid(&access_token).await);

        // Now call the token endpoint to get an access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client.client_id,
            }));

        let first_response = state.request(request).await;
        first_response.assert_status(StatusCode::OK);
        let first_response: AccessTokenResponse = first_response.json();

        // Call a second time, it should work, as we haven't done anything yet with the
        // token
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client.client_id,
            }));

        let second_response = state.request(request).await;
        second_response.assert_status(StatusCode::OK);
        let second_response: AccessTokenResponse = second_response.json();

        // Check that we got new tokens
        assert_ne!(first_response.access_token, second_response.access_token);
        assert_ne!(first_response.refresh_token, second_response.refresh_token);

        // Check that the old-new token is invalid
        assert!(
            !state
                .is_access_token_valid(&first_response.access_token)
                .await
        );

        // Check that the new-new token is valid
        assert!(
            state
                .is_access_token_valid(&second_response.access_token)
                .await
        );

        // Do a third refresh, this one should not work, as we've used the new
        // access token
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client.client_id,
            }));

        let third_response = state.request(request).await;
        third_response.assert_status(StatusCode::BAD_REQUEST);

        // The other reason we consider a new refresh token to be 'used' is if
        // it was already used in a refresh
        // So, if we do a refresh with the second_response.refresh_token, then
        // another refresh with the result, redoing one with
        // second_response.refresh_token again should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": second_response.refresh_token,
                "client_id": client.client_id,
            }));

        // This one is fine
        let fourth_response = state.request(request).await;
        fourth_response.assert_status(StatusCode::OK);
        let fourth_response: AccessTokenResponse = fourth_response.json();

        // Do another one, it should be fine as well
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": fourth_response.refresh_token,
                "client_id": client.client_id,
            }));

        let fifth_response = state.request(request).await;
        fifth_response.assert_status(StatusCode::OK);

        // But now, if we re-do with the second_response.refresh_token, it should
        // fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": second_response.refresh_token,
                "client_id": client.client_id,
            }));

        let sixth_response = state.request(request).await;
        sixth_response.assert_status(StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_client_credentials(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["client_credentials"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;
        let client_secret = response.client_secret.expect("to have a client secret");

        // Call the token endpoint with an empty scope
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: AccessTokenResponse = response.json();
        assert!(response.refresh_token.is_none());
        assert!(response.expires_in.is_some());
        assert!(response.scope.is_none());

        // Revoke the token
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": response.access_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        // We should be allowed to ask for the GraphQL API scope
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "urn:mas:graphql:*"
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: AccessTokenResponse = response.json();
        assert!(response.refresh_token.is_none());
        assert!(response.expires_in.is_some());
        assert_eq!(response.scope, Some("urn:mas:graphql:*".parse().unwrap()));

        // Revoke the token
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": response.access_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        // We should be NOT allowed to ask for the MAS admin scope
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "urn:mas:admin"
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::InvalidScope);

        // Now, if we add the client to the admin list in the policy, it should work
        let state = {
            let mut state = state;
            state.policy_factory = crate::test_utils::policy_factory(
                "example.com",
                serde_json::json!({
                    "admin_clients": [client_id]
                }),
            )
            .await
            .unwrap();
            state
        };

        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "urn:mas:admin"
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: AccessTokenResponse = response.json();
        assert!(response.refresh_token.is_none());
        assert!(response.expires_in.is_some());
        assert_eq!(response.scope, Some("urn:mas:admin".parse().unwrap()));

        // Revoke the token
        let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
            "token": response.access_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_device_code_grant(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "token_endpoint_auth_method": "none",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
                "response_types": [],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;

        // Start a device code grant
        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let device_grant: DeviceAuthorizationResponse = response.json();

        // Poll the token endpoint, it should be pending
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_grant.device_code,
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::AuthorizationPending);

        // Let's provision a user and create a browser session for them. This part is
        // hard to test with just HTTP requests, so we'll use the repository
        // directly.
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

        // Find the grant
        let grant = repo
            .oauth2_device_code_grant()
            .find_by_user_code(&device_grant.user_code)
            .await
            .unwrap()
            .unwrap();

        // And fulfill it
        let grant = repo
            .oauth2_device_code_grant()
            .fulfill(&state.clock, grant, &browser_session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now call the token endpoint to get an access token.
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": grant.device_code,
                "client_id": client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: AccessTokenResponse = response.json();

        // Check that the token is valid
        assert!(state.is_access_token_valid(&response.access_token).await);
        // We advertised the refresh token grant type, so we should have a refresh token
        assert!(response.refresh_token.is_some());
        // We asked for the openid scope, so we should have an ID token
        assert!(response.id_token.is_some());

        // Calling it again should fail
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": grant.device_code,
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::InvalidGrant);

        // Do another grant and make it expire
        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let device_grant: DeviceAuthorizationResponse = response.json();

        // Poll the token endpoint, it should be pending
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_grant.device_code,
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::AuthorizationPending);

        state.clock.advance(Duration::try_hours(1).unwrap());

        // Poll again, it should be expired
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_grant.device_code,
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::ExpiredToken);

        // Do another grant and reject it
        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let device_grant: DeviceAuthorizationResponse = response.json();

        // Find the grant and reject it
        let mut repo = state.repository().await.unwrap();

        // Find the grant
        let grant = repo
            .oauth2_device_code_grant()
            .find_by_user_code(&device_grant.user_code)
            .await
            .unwrap()
            .unwrap();

        // And reject it
        let grant = repo
            .oauth2_device_code_grant()
            .reject(&state.clock, grant, &browser_session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Poll the token endpoint, it should be rejected
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": grant.device_code,
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::AccessDenied);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unsupported_grant(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["password"],
                "response_types": [],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;
        let client_secret = response.client_secret.expect("to have a client secret");

        // Call the token endpoint with an unsupported grant type
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "password",
                "client_id": client_id,
                "client_secret": client_secret,
                "username": "john",
                "password": "hunter2",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let ClientError { error, .. } = response.json();
        assert_eq!(error, ClientErrorCode::UnsupportedGrantType);
    }
}
