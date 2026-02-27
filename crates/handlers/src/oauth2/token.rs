// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

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
    AuthorizationGrantStage, BoxClock, BoxRng, Client, Clock, Device, DeviceCodeGrantState,
    SiteConfig, TokenType,
};
use mas_i18n::DataLocale;
use mas_keystore::{Encrypter, Keystore};
use mas_matrix::HomeserverConnection;
use mas_oidc_client::types::scope::ScopeToken;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{
    BoxRepository, Pagination, RepositoryAccess,
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository,
        OAuth2RefreshTokenRepository, OAuth2SessionRepository,
    },
    upstream_oauth2::{
        UpstreamOAuthLinkFilter, UpstreamOAuthLinkTokenRepository, UpstreamOAuthProviderRepository,
    },
    user::{BrowserSessionRepository, UserRepository},
};
use mas_templates::{DeviceNameContext, TemplateContext, Templates};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce::CodeChallengeError,
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, ClientCredentialsGrant,
        DeviceCodeGrant, GrantType, RefreshTokenGrant, TokenExchangeGrant,
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

    #[error("subject token is invalid or expired")]
    SubjectTokenInvalid,

    #[error("upstream provider not found")]
    UpstreamProviderNotFound,

    #[error("user has no link to the requested upstream provider")]
    NoUpstreamLink,

    #[error("no stored token for this upstream link")]
    NoUpstreamToken,

    #[error("failed to refresh upstream token")]
    UpstreamTokenRefreshFailed(#[source] anyhow::Error),
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
                | Self::UpstreamTokenRefreshFailed(_)
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
            | Self::UpstreamTokenRefreshFailed(_) => (
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

            Self::SubjectTokenInvalid => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidGrant)
                        .with_description("subject_token is invalid or expired".to_owned()),
                ),
            ),

            Self::UpstreamProviderNotFound => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidGrant).with_description(
                        "no upstream provider found matching the audience".to_owned(),
                    ),
                ),
            ),

            Self::NoUpstreamLink => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidGrant).with_description(
                        "user has no link to the requested upstream provider".to_owned(),
                    ),
                ),
            ),

            Self::NoUpstreamToken => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidGrant)
                        .with_description("no stored token for this upstream link".to_owned()),
                ),
            ),
        };

        (sentry_event_id, response).into_response()
    }
}

impl_from_error_for_route!(mas_i18n::DataError);
impl_from_error_for_route!(mas_templates::TemplateError);
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
    State(metadata_cache): State<crate::upstream_oauth2::cache::MetadataCache>,
    State(templates): State<Templates>,
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
                &templates,
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
        AccessTokenRequest::TokenExchange(grant) => {
            token_exchange_grant(
                &mut rng,
                &clock,
                &activity_tracker,
                &grant,
                &client,
                &encrypter,
                &http_client,
                &key_store,
                &metadata_cache,
                repo,
                policy,
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
    templates: &Templates,
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

    // Generate a device name
    let lang: DataLocale = authz_grant.locale.as_deref().unwrap_or("en").parse()?;
    let ctx = DeviceNameContext::new(client.clone(), user_agent.clone()).with_language(lang);
    let device_name = templates.render_device_name(&ctx)?;

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
    for scope in &*session.scope {
        if let Some(device) = Device::from_scope_token(scope) {
            homeserver
                .upsert_device(
                    &browser_session.user.username,
                    device.as_str(),
                    Some(&device_name),
                )
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

        // Check if the associated access token was already used.
        //
        // If the access token is no longer present, we assume it was *not* used.
        // Tokens can disappear for two main reasons:
        //
        //  - revoked access tokens are deleted after 1 hour
        //  - expired access tokens are deleted after 30 days
        //
        // Revoked tokens are not an issue, as the associated refresh token is also
        // revoked. For expired tokens, however, we are effectively losing the
        // ability to prevent the client from performing a bad double-refresh.
        // This measure is intended to enhance security when a refresh token
        // leaks. However, the primary goal is to ensure that we do not maintain
        // two active branches of the refresh token tree.
        //
        // Consider these two scenarios:
        //
        //   - Refresh token A is consumed, issuing refresh token B and access token C.
        //   - The client uses access token C.
        //   - Access token C expires after some time.
        //   - If the client then attempts to use refresh token A again:
        //      - If access token C is still present, the refresh will be rightfully
        //        declined, as we have proof that it received the new set of tokens.
        //      - If access token C was cleaned up, the refresh will succeed, issuing
        //        new tokens but invalidating refresh token B and the original access
        //        token C.
        if let Some(access_token_id) = next_refresh_token.access_token_id {
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

            // This could be a double-refresh, see below
            repo.oauth2_access_token()
                .revoke(clock, next_access_token)
                .await?;
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
            session_counts: None,
            scope: &scope,
            grant_type: mas_policy::GrantType::ClientCredentials,
            upstream_provider: None,
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
    for scope in &*session.scope {
        if let Some(device) = Device::from_scope_token(scope) {
            homeserver
                .upsert_device(&browser_session.user.username, device.as_str(), None)
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

/// The expected `subject_token_type` for RFC 8693 token exchange.
const ACCESS_TOKEN_TYPE_URN: &str = "urn:ietf:params:oauth:token-type:access_token";

#[tracing::instrument(
    name = "handlers.oauth2.token.token_exchange",
    fields(client.id = %client.id),
    skip_all,
)]
async fn token_exchange_grant(
    rng: &mut BoxRng,
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    grant: &TokenExchangeGrant,
    client: &Client,
    encrypter: &Encrypter,
    http_client: &reqwest::Client,
    key_store: &Keystore,
    metadata_cache: &crate::upstream_oauth2::cache::MetadataCache,
    mut repo: BoxRepository,
    mut policy: Policy,
    user_agent: Option<String>,
) -> Result<(AccessTokenResponse, BoxRepository), RouteError> {
    // 1. Validate subject_token_type
    if grant.subject_token_type != ACCESS_TOKEN_TYPE_URN {
        return Err(RouteError::BadRequest);
    }

    // 2. Parse and validate the subject_token as a MAS access token
    let token_type =
        TokenType::check(&grant.subject_token).map_err(|_| RouteError::SubjectTokenInvalid)?;

    if token_type != TokenType::AccessToken {
        return Err(RouteError::SubjectTokenInvalid);
    }

    // 3. Look up the access token and its session
    let access_token = repo
        .oauth2_access_token()
        .find_by_token(&grant.subject_token)
        .await?
        .ok_or(RouteError::SubjectTokenInvalid)?;

    if !access_token.is_valid(clock.now()) {
        return Err(RouteError::SubjectTokenInvalid);
    }

    let session = repo
        .oauth2_session()
        .lookup(access_token.session_id)
        .await?
        .ok_or(RouteError::NoSuchOAuthSession(access_token.session_id))?;

    if !session.is_valid() {
        return Err(RouteError::SubjectTokenInvalid);
    }

    // Token exchange requires a user
    let user_id = session.user_id.ok_or(RouteError::SubjectTokenInvalid)?;
    let user = repo
        .user()
        .lookup(user_id)
        .await?
        .ok_or(RouteError::SubjectTokenInvalid)?;

    if !user.is_valid() {
        return Err(RouteError::SubjectTokenInvalid);
    }

    // 4. Resolve the upstream provider from audience
    let audience = grant
        .audience
        .as_deref()
        .ok_or(RouteError::UpstreamProviderNotFound)?;

    let provider = if let Ok(id) = audience.parse::<Ulid>() {
        // Try as a ULID
        repo.upstream_oauth_provider()
            .lookup(id)
            .await?
            .filter(mas_data_model::UpstreamOAuthProvider::enabled)
    } else {
        // Try as an issuer URL
        repo.upstream_oauth_provider()
            .find_by_issuer(audience)
            .await?
    }
    .ok_or(RouteError::UpstreamProviderNotFound)?;

    // 5. Evaluate policy
    let scope = grant
        .scope
        .clone()
        .unwrap_or_else(|| std::iter::empty::<scope::ScopeToken>().collect());

    let provider_id_str = provider.id.to_string();
    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            user: Some(&user),
            client,
            session_counts: None,
            scope: &scope,
            grant_type: mas_policy::GrantType::TokenExchange,
            upstream_provider: Some(mas_policy::UpstreamProviderInfo {
                id: &provider_id_str,
                issuer: provider.issuer.as_deref(),
                human_name: provider.human_name.as_deref(),
            }),
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;

    if !res.valid() {
        return Err(RouteError::DeniedByPolicy(res));
    }

    // 6. Find the upstream link for this user + provider
    let filter = UpstreamOAuthLinkFilter::new()
        .for_user(&user)
        .for_provider(&provider);

    let page = repo
        .upstream_oauth_link()
        .list(filter, Pagination::first(1))
        .await?;

    let link = page
        .edges
        .into_iter()
        .next()
        .map(|edge| edge.node)
        .ok_or(RouteError::NoUpstreamLink)?;

    // 7. Find the stored token for this link
    let mut link_token = repo
        .upstream_oauth_link_token()
        .find_by_link(&link)
        .await?
        .ok_or(RouteError::NoUpstreamToken)?;

    // 8. If the token is expired and we have a refresh token, auto-refresh
    if link_token.is_expired(clock.now()) && link_token.has_refresh_token() {
        let encrypted_refresh_token = link_token
            .encrypted_refresh_token
            .as_deref()
            .expect("refresh token presence already checked");
        let refresh_token_bytes = encrypter
            .decrypt_string(encrypted_refresh_token)
            .map_err(|e| RouteError::Internal(Box::new(e)))?;
        let refresh_token = String::from_utf8(refresh_token_bytes)
            .map_err(|e| RouteError::Internal(Box::new(e)))?;

        let mut lazy_metadata = crate::upstream_oauth2::cache::LazyProviderInfos::new(
            metadata_cache,
            &provider,
            http_client,
        );
        let token_endpoint = lazy_metadata
            .token_endpoint()
            .await
            .map_err(|e| RouteError::UpstreamTokenRefreshFailed(e.into()))?
            .clone();

        let client_credentials = crate::upstream_oauth2::client_credentials_for_provider(
            &provider,
            &token_endpoint,
            key_store,
            encrypter,
        )
        .map_err(|e| RouteError::UpstreamTokenRefreshFailed(e.into()))?;

        let (token_response, _id_token) =
            mas_oidc_client::requests::refresh_token::refresh_access_token(
                http_client,
                client_credentials,
                &token_endpoint,
                refresh_token,
                None,
                None,
                None,
                clock.now(),
                rng,
            )
            .await
            .map_err(|e| RouteError::UpstreamTokenRefreshFailed(e.into()))?;

        // Encrypt and store the new tokens
        let new_encrypted_access_token = encrypter
            .encrypt_to_string(token_response.access_token.as_bytes())
            .map_err(|e| RouteError::Internal(Box::new(e)))?;

        let new_encrypted_refresh_token = token_response
            .refresh_token
            .as_deref()
            .map(|rt| encrypter.encrypt_to_string(rt.as_bytes()))
            .transpose()
            .map_err(|e| RouteError::Internal(Box::new(e)))?;

        let new_expires_at = token_response.expires_in.map(|d| clock.now() + d);

        link_token = repo
            .upstream_oauth_link_token()
            .update_tokens(
                clock,
                link_token,
                new_encrypted_access_token,
                new_encrypted_refresh_token,
                new_expires_at,
            )
            .await?;
    }

    // 9. Decrypt the upstream access token
    let decrypted = encrypter
        .decrypt_string(&link_token.encrypted_access_token)
        .map_err(|e| RouteError::Internal(Box::new(e)))?;
    let upstream_access_token =
        String::from_utf8(decrypted).map_err(|e| RouteError::Internal(Box::new(e)))?;

    // 10. Build the response
    let mut response = AccessTokenResponse::new(upstream_access_token);
    response.issued_token_type = Some(ACCESS_TOKEN_TYPE_URN.to_owned());

    if let Some(expires_at) = link_token.access_token_expires_at {
        let remaining = expires_at - clock.now();
        if remaining > Duration::zero() {
            response = response.with_expires_in(remaining);
        }
    }

    if let Some(ref token_scope) = link_token.token_scope
        && let Ok(parsed_scope) = token_scope.parse()
    {
        response = response.with_scope(parsed_scope);
    }

    Ok((response, repo))
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
        let fifth_response: AccessTokenResponse = fifth_response.json();

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

        // One edge-case scenario: after 30 days, expired access tokens are
        // deleted, so we can't track accurately if the refresh successful or
        // not. In this case we chose to allow the refresh to succeed to avoid
        // spuriously logging out the user.

        // Make sure to mark the fifth access token as used
        assert!(
            state
                .is_access_token_valid(&fifth_response.access_token)
                .await
        );

        // Make sure to run all the cleanup tasks
        // We run the job queue once before advancing the clock to make sure the
        // scheduled jobs get scheduled to a time before we advanced the clock
        state.run_jobs_in_queue().await;
        state.clock.advance(Duration::days(31));
        state.run_jobs_in_queue().await;

        // We're not supposed to be able to use the fourth refresh token, but here we
        // are
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": fourth_response.refresh_token,
                "client_id": client.client_id,
            }));

        let seventh_response = state.request(request).await;
        seventh_response.assert_status(StatusCode::OK);

        // And the refresh token we had on the fifth response should now be invalid
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": fifth_response.refresh_token,
                "client_id": client.client_id,
            }));

        let eighth_response = state.request(request).await;
        eighth_response.assert_status(StatusCode::BAD_REQUEST);
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

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_token_exchange_grant(pool: PgPool) {
        use mas_data_model::{
            UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
            UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderTokenAuthMethod,
        };
        use mas_iana::jose::JsonWebSignatureAlg;
        use mas_storage::upstream_oauth2::{
            UpstreamOAuthLinkRepository, UpstreamOAuthLinkTokenRepository,
            UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
        };

        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // 1. Register a client that supports token exchange
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "redirect_uris": ["https://example.com/callback"],
                "grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let ClientRegistrationResponse { client_id, .. } = response.json();

        // 2. Create user, browser session, OAuth session, and access token
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

        let subject_token_str = TokenType::AccessToken.generate(&mut state.rng());
        let _access_token = repo
            .oauth2_access_token()
            .add(
                &mut state.rng(),
                &state.clock,
                &session,
                subject_token_str.clone(),
                Some(Duration::try_hours(1).unwrap()),
            )
            .await
            .unwrap();

        // 3. Create an upstream provider
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut state.rng(),
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://upstream.example.com/".to_owned()),
                    human_name: Some("Test Provider".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    client_id: "upstream-client-id".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: UpstreamOAuthProviderDiscoveryMode::Disabled,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                },
            )
            .await
            .unwrap();

        // 4. Create a link between the user and the upstream provider
        let link = repo
            .upstream_oauth_link()
            .add(
                &mut state.rng(),
                &state.clock,
                &provider,
                "upstream-subject".to_owned(),
                None,
            )
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&link, &user)
            .await
            .unwrap();

        // 5. Store an encrypted upstream token
        let upstream_access_token = "upstream-access-token-value";
        let encrypted_access_token = state
            .encrypter
            .encrypt_to_string(upstream_access_token.as_bytes())
            .unwrap();

        let _link_token = repo
            .upstream_oauth_link_token()
            .add(
                &mut state.rng(),
                &state.clock,
                &link,
                encrypted_access_token,
                None,
                Some(state.clock.now() + Duration::try_hours(1).unwrap()),
                Some("openid".to_owned()),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // 6. Perform the token exchange
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token_str,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": provider.id.to_string(),
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let token_response: AccessTokenResponse = response.json();
        assert_eq!(token_response.access_token, upstream_access_token);
        assert_eq!(
            token_response.issued_token_type.as_deref(),
            Some("urn:ietf:params:oauth:token-type:access_token")
        );

        // 7. Test with issuer as audience (should also work)
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token_str,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "https://upstream.example.com/",
                "client_id": client.client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let token_response: AccessTokenResponse = response.json();
        assert_eq!(token_response.access_token, upstream_access_token);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_token_exchange_errors(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Register a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "redirect_uris": ["https://example.com/callback"],
                "grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let ClientRegistrationResponse { client_id, .. } = response.json();

        // Invalid subject_token
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": "invalid-token",
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "https://upstream.example.com/",
                "client_id": client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        // Create a valid access token but no upstream link
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "bob".to_owned())
            .await
            .unwrap();

        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();

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

        let subject_token_str = TokenType::AccessToken.generate(&mut state.rng());
        let _access_token = repo
            .oauth2_access_token()
            .add(
                &mut state.rng(),
                &state.clock,
                &session,
                subject_token_str.clone(),
                Some(Duration::try_hours(1).unwrap()),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // No audience → error
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token_str,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "client_id": client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        // Unknown audience → error
        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token_str,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "https://unknown.example.com/",
                "client_id": client_id,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
