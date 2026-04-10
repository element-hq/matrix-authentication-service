// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

use axum::{Json, extract::State, response::IntoResponse};
use axum_extra::typed_header::TypedHeader;
use chrono::Duration;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::{
    BoxClock, BoxRng, Clock, CompatSession, CompatSsoLoginState, Device, SessionLimitConfig,
    SiteConfig, TokenType, User,
};
use mas_matrix::HomeserverConnection;
use mas_policy::{Policy, Requester, Violation, ViolationVariant, model::CompatLogin};
use mas_storage::{
    BoxRepository, BoxRepositoryFactory, Pagination, RepositoryAccess,
    compat::{
        CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionFilter,
        CompatSessionRepository, CompatSsoLoginRepository,
    },
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    user::{UserPasswordRepository, UserRepository},
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::{DurationMilliSeconds, serde_as, skip_serializing_none};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{MatrixError, MatrixJsonBody};
use crate::{
    BoundActivityTracker, Limiter, METER, RequesterFingerprint, impl_from_error_for_route,
    passwords::{PasswordManager, PasswordVerificationResult},
    rate_limit::PasswordCheckLimitedError,
    session::count_user_sessions_for_limiting,
};

static LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.compat.login_request")
        .with_description("How many compatibility login requests have happened")
        .with_unit("{request}")
        .build()
});
const TYPE: Key = Key::from_static_str("type");
const RESULT: Key = Key::from_static_str("result");

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
        oauth_aware_preferred: bool,
        /// DEPRECATED: Use `oauth_aware_preferred` instead. We will remove this
        /// once enough clients support the stable name `oauth_aware_preferred`.
        #[serde(rename = "org.matrix.msc3824.delegated_oidc_compatibility")]
        unstable_delegated_oidc_compatibility: bool,
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

#[tracing::instrument(name = "handlers.compat.login.get", skip_all)]
pub(crate) async fn get(State(password_manager): State<PasswordManager>) -> impl IntoResponse {
    let flows = if password_manager.is_enabled() {
        vec![
            LoginType::Password,
            LoginType::Sso {
                identity_providers: vec![],
                oauth_aware_preferred: true,
                unstable_delegated_oidc_compatibility: true,
            },
            LoginType::Token,
        ]
    } else {
        vec![
            LoginType::Sso {
                identity_providers: vec![],
                oauth_aware_preferred: true,
                unstable_delegated_oidc_compatibility: true,
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

    /// ID of the client device.
    /// If this does not correspond to a known client device, a new device will
    /// be created. The given device ID must not be the same as a
    /// cross-signing key ID. The server will auto-generate a `device_id` if
    /// this is not specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    initial_device_display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Credentials {
    #[serde(rename = "m.login.password")]
    Password {
        identifier: Option<Identifier>,
        // This property has been deprecated for a while, but some tools still use it.
        user: Option<String>,
        password: String,
    },

    #[serde(rename = "m.login.token")]
    Token { token: String },

    #[serde(other)]
    Unsupported,
}

impl Credentials {
    fn login_type(&self) -> &'static str {
        match self {
            Self::Password { .. } => "m.login.password",
            Self::Token { .. } => "m.login.token",
            Self::Unsupported => "unsupported",
        }
    }
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
    device_id: Option<Device>,
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

    #[error("unsupported identifier type")]
    UnsupportedIdentifier,

    #[error("missing property 'identifier'")]
    MissingIdentifier,

    #[error("user not found")]
    UserNotFound,

    #[error("user has no password")]
    NoPassword,

    #[error("password verification failed")]
    PasswordMismatch,

    #[error("request rate limited")]
    RateLimited(#[from] PasswordCheckLimitedError),

    #[error("login took too long")]
    LoginTookTooLong,

    #[error("invalid login token")]
    InvalidLoginToken,

    #[error("user is locked")]
    UserLocked,

    #[error("failed to provision device")]
    ProvisionDeviceFailed(#[source] anyhow::Error),

    #[error("login rejected by policy")]
    PolicyRejected,

    #[error("login rejected by policy (hard session limit reached)")]
    PolicyHardSessionLimitReached,
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::EvaluationError);

impl From<anyhow::Error> for RouteError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err.into())
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id =
            record_error!(self, Self::Internal(_) | Self::ProvisionDeviceFailed(_));
        LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        let response = match self {
            Self::Internal(_) | Self::ProvisionDeviceFailed(_) => MatrixError {
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
                errcode: "M_UNKNOWN",
                error: "Invalid login type",
                status: StatusCode::BAD_REQUEST,
            },
            Self::UnsupportedIdentifier => MatrixError {
                errcode: "M_UNKNOWN",
                error: "Unsupported login identifier",
                status: StatusCode::BAD_REQUEST,
            },
            Self::MissingIdentifier => MatrixError {
                errcode: "M_BAD_JSON",
                error: "Missing property 'identifier",
                status: StatusCode::BAD_REQUEST,
            },
            Self::UserNotFound | Self::NoPassword | Self::PasswordMismatch => MatrixError {
                errcode: "M_FORBIDDEN",
                error: "Invalid username/password",
                status: StatusCode::FORBIDDEN,
            },
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
            Self::UserLocked => MatrixError {
                errcode: "M_USER_LOCKED",
                error: "User account has been locked",
                status: StatusCode::UNAUTHORIZED,
            },
            Self::PolicyRejected => MatrixError {
                errcode: "M_FORBIDDEN",
                error: "Login denied by the policy enforced by this service",
                status: StatusCode::FORBIDDEN,
            },
            Self::PolicyHardSessionLimitReached => MatrixError {
                errcode: "M_FORBIDDEN",
                error: "You have reached your hard device limit. Please visit your account page to sign some out.",
                status: StatusCode::FORBIDDEN,
            },
        };

        (sentry_event_id, response).into_response()
    }
}

#[tracing::instrument(name = "handlers.compat.login.post", skip_all)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(password_manager): State<PasswordManager>,
    State(repository_factory): State<BoxRepositoryFactory>,
    activity_tracker: BoundActivityTracker,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    State(site_config): State<SiteConfig>,
    State(limiter): State<Limiter>,
    mut policy: Policy,
    requester: RequesterFingerprint,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    MatrixJsonBody(input): MatrixJsonBody<RequestBody>,
) -> Result<impl IntoResponse, RouteError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    let login_type = input.credentials.login_type();
    let mut repo = repository_factory.create().await?;
    let (mut session, user) = match (password_manager.is_enabled(), input.credentials) {
        (
            true,
            Credentials::Password {
                identifier,
                user,
                password,
            },
        ) => {
            // This is to support both the (very) old and deprecated 'user' property, with
            // the same behavior as Synapse: it takes precendence over the 'identifier' if
            // provided
            let user = match (identifier, user) {
                (Some(Identifier::User { user }), None) | (_, Some(user)) => user,
                (Some(Identifier::Unsupported), None) => {
                    return Err(RouteError::UnsupportedIdentifier);
                }
                (None, None) => {
                    return Err(RouteError::MissingIdentifier);
                }
            };

            // Try getting the localpart out of the MXID
            let username = homeserver.localpart(&user).unwrap_or(&user);

            user_password_login(
                &mut rng,
                &clock,
                &password_manager,
                &limiter,
                requester,
                &mut repo,
                &mut policy,
                Requester {
                    ip_address: activity_tracker.ip(),
                    user_agent: user_agent.clone(),
                },
                site_config.session_limit.as_ref(),
                username,
                password,
                input.device_id, // TODO check for validity
                input.initial_device_display_name,
            )
            .await?
        }

        (_, Credentials::Token { token }) => {
            token_login(
                &mut rng,
                &clock,
                &mut repo,
                &mut policy,
                Requester {
                    ip_address: activity_tracker.ip(),
                    user_agent: user_agent.clone(),
                },
                site_config.session_limit.as_ref(),
                &token,
                input.device_id,
                input.initial_device_display_name,
            )
            .await?
        }

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

    // Ideally, we'd keep the lock whilst we actually create the device, but we
    // really want to stop holding the transaction while we talk to the
    // homeserver.
    //
    // In practice, this is fine, because:
    // - the session exists after we commited the transaction, so a sync job won't
    //   try to delete it
    // - we've acquired a lock on the user before creating the session, meaning
    //   we've made sure that sync jobs finished before we create the new session
    // - we're in the read-commited isolation level, which means the sync will see
    //   what we've committed and won't try to delete the session once we release
    //   the lock
    repo.save().await?;

    activity_tracker
        .record_compat_session(&clock, &session)
        .await;

    // This session will have for sure the device on it, both methods create a
    // device
    let Some(device) = &session.device else {
        unreachable!()
    };

    // Now we can create the device on the homeserver, without holding the
    // transaction
    if let Err(err) = homeserver
        .upsert_device(
            &user.username,
            device.as_str(),
            session.human_name.as_deref(),
        )
        .await
    {
        // Something went wrong, let's end this session and schedule a device sync
        let mut repo = repository_factory.create().await?;
        let session = repo.compat_session().finish(&clock, session).await?;

        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SyncDevicesJob::new_for_id(session.user_id),
            )
            .await?;

        repo.save().await?;

        return Err(RouteError::ProvisionDeviceFailed(err));
    }

    LOGIN_COUNTER.add(
        1,
        &[
            KeyValue::new(TYPE, login_type),
            KeyValue::new(RESULT, "success"),
        ],
    );

    Ok(Json(ResponseBody {
        access_token: access_token.token,
        device_id: session.device,
        user_id,
        refresh_token,
        expires_in_ms: expires_in,
    }))
}

/// Given the violations from [`Policy::evaluate_compat_login`], return the
/// appropriate `RouteError` response.
async fn process_violations_for_compat_login(
    clock: &dyn Clock,
    repo: &mut BoxRepository,
    session_limit_config: Option<&SessionLimitConfig>,
    user: &User,
    violations: Vec<Violation>,
) -> Result<(), RouteError> {
    // We're using slice syntax here so we can match easily
    match &violations[..] {
        // If the only violation is having reached the session limit, we might be
        // able to resolve the situation.
        //
        // We don't trigger this if there was some other violation anyway, since
        // that means that removing a session wouldn't actually unblock the login.
        [
            Violation {
                variant: Some(ViolationVariant::TooManySessions),
                ..
            },
        ] => {
            let session_limit_config = session_limit_config
                    .expect("We should have a `session_limit` config if we are seeing a `TooManySessions` violation. \
                    This is most likely a programming error.");

            // TODO: This should come from `ViolationVariant::TooManySessions`
            let need_to_remove: u32 = 1;
            let need_to_remove_usize = usize::try_from(need_to_remove).map_err(|err| {
                RouteError::Internal(
                    anyhow::anyhow!("Unable to convert `need_to_remove` to usize: {err}").into(),
                )
            })?;

            // When logging in with the compatibility API, there is no way for us to
            // display any web UI for people to remove devices, so we instead
            // automatically remove their oldest devices (when `hard_limit_eviction`
            // is configured).
            if session_limit_config.hard_limit_eviction {
                // Find the least recently used (LRU) compat sessions
                //
                // In the future, it may be nice to avoid sessions with
                // cryptographic state (what does that mean exactly? keys uploaded
                // for device?).
                //
                // FIXME: We could potentially use
                // `repo.compat_session().finish_bulk(...)` if it had the ability to
                // limit and order.
                let lru_compat_sessions = {
                    // TODO: In the future, instead of all of this faff, we can simply order
                    // by `last_active_at`
                    //
                    // XXX: Since we can't order by `last_active_at` yet, we instead filter
                    // the list down to "inactive" sessions (`last_active_at` > 90 days
                    // ago). And by the nature of
                    // [`mas_data_model::compat::CompatSession::id`] being a `Ulid`/`Uuid`
                    // (the query is ordered by `compat_session_id`), the first bytes are a
                    // timestamp so we'll be getting the 'oldest created' sessions which is
                    // another good proxy.

                    let mut edges_to_consider = Vec::new();

                    // First, find the "inactive" sessions
                    let inactive_threshold_date = clock.now() - Duration::days(90);
                    let inactive_compat_session_page = repo
                        .compat_session()
                        .list(
                            CompatSessionFilter::new()
                                .for_user(user)
                                .active_only()
                                .with_last_active_before(inactive_threshold_date),
                            // We fetch a minimum of 100 sessions (more than we need in
                            // normal cases) so we can sort by `last_active_at` after it
                            // gets back from the database and can get even closer to
                            // removing the oldest sessions.
                            Pagination::first(std::cmp::max(need_to_remove_usize, 100)),
                        )
                        .await?;
                    edges_to_consider.extend(inactive_compat_session_page.edges);

                    // If there aren't enough "inactive" sessions, supplement with active ones
                    if edges_to_consider.len() < need_to_remove_usize {
                        let active_compat_session_page = repo
                            .compat_session()
                            .list(
                                // If we try to use
                                // `.with_last_active_after(inactive_threshold_date)`
                                // here, it will exclude all of the rows where
                                // `last_active_at` is null which we want to include.
                                CompatSessionFilter::new().for_user(user).active_only(),
                                // We fetch a minimum of 100 sessions (more than we need in
                                // normal cases) so we can sort by `last_active_at` after it
                                // gets back from the database and can get even closer to
                                // removing the oldest sessions.
                                Pagination::first(std::cmp::max(need_to_remove_usize, 100)),
                            )
                            .await?;
                        edges_to_consider.extend(active_compat_session_page.edges);
                    }

                    // De-duplicate the sessions across both pages
                    let compat_session_map = {
                        let mut compat_session_map = HashMap::new();
                        for edge in edges_to_consider {
                            let (compat_session, _) = edge.node;
                            compat_session_map.insert(compat_session.id, compat_session);
                        }
                        compat_session_map
                    };

                    // List of compat sessions sorted by `last_active_at` ascending
                    let sorted_compat_sessions = {
                        let mut compat_sessions: Vec<mas_data_model::CompatSession> =
                            compat_session_map.into_values().collect();
                        // Sort by `last_active_at` (ascending)
                        compat_sessions.sort_by_key(|compat_session| compat_session.last_active_at);
                        compat_sessions
                    };

                    sorted_compat_sessions
                };

                // For now, we only automatically clean up compatibility sessions.
                // If there aren't enough sessions that we could clean up, we just
                // throw an error with an explanation.
                if lru_compat_sessions.len() < need_to_remove_usize {
                    return Err(RouteError::PolicyHardSessionLimitReached);
                }

                // Remove the sessions (only as much as necessary, `need_to_remove`)
                for compat_session in &lru_compat_sessions[0..need_to_remove_usize] {
                    repo.compat_session()
                        .finish(clock, compat_session.to_owned())
                        .await?;
                }
            } else {
                // Tell the user about the limit
                return Err(RouteError::PolicyHardSessionLimitReached);
            }
        }
        // Nothing is wrong
        [] => return Ok(()),
        // Just throw an error for any other violation
        _violations => {
            // FIXME: We should be exposing the violations to the user
            return Err(RouteError::PolicyRejected);
        }
    }

    Ok(())
}

async fn token_login(
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    repo: &mut BoxRepository,
    policy: &mut Policy,
    requester: Requester,
    session_limit_config: Option<&SessionLimitConfig>,
    token: &str,
    requested_device_id: Option<String>,
    initial_device_display_name: Option<String>,
) -> Result<(CompatSession, User), RouteError> {
    let login = repo
        .compat_sso_login()
        .find_by_token(token)
        .await?
        .ok_or(RouteError::InvalidLoginToken)?;

    let now = clock.now();
    let browser_session_id = match login.state {
        CompatSsoLoginState::Pending => {
            tracing::error!(
                compat_sso_login.id = %login.id,
                "Exchanged a token for a login that was not fullfilled yet"
            );
            return Err(RouteError::InvalidLoginToken);
        }
        CompatSsoLoginState::Fulfilled {
            fulfilled_at,
            browser_session_id,
            ..
        } => {
            if now > fulfilled_at + Duration::microseconds(30 * 1000 * 1000) {
                return Err(RouteError::LoginTookTooLong);
            }

            browser_session_id
        }
        CompatSsoLoginState::Exchanged {
            exchanged_at,
            compat_session_id,
            ..
        } => {
            if now > exchanged_at + Duration::microseconds(30 * 1000 * 1000) {
                // TODO: log that session out
                tracing::error!(
                    compat_sso_login.id = %login.id,
                    compat_session.id = %compat_session_id,
                    "Login token exchanged a second time more than 30s after"
                );
            }

            return Err(RouteError::InvalidLoginToken);
        }
    };

    let Some(browser_session) = repo.browser_session().lookup(browser_session_id).await? else {
        tracing::error!(
            compat_sso_login.id = %login.id,
            browser_session.id = %browser_session_id,
            "Attempt to exchange login token but no associated browser session found"
        );
        return Err(RouteError::InvalidLoginToken);
    };
    if !browser_session.active() || !browser_session.user.is_valid() {
        tracing::info!(
            compat_sso_login.id = %login.id,
            browser_session.id = %browser_session_id,
            "Attempt to exchange login token but browser session is not active"
        );
        return Err(
            if browser_session.finished_at.is_some()
                || browser_session.user.deactivated_at.is_some()
            {
                RouteError::InvalidLoginToken
            } else {
                RouteError::UserLocked
            },
        );
    }

    // We're about to create a device, let's explicitly acquire a lock, so that
    // any concurrent sync will read after we've committed
    repo.user()
        .acquire_lock_for_sync(&browser_session.user)
        .await?;

    let device = if let Some(requested_device_id) = requested_device_id {
        Device::from(requested_device_id)
    } else {
        Device::generate(rng)
    };

    let session_replaced = repo
        .app_session()
        .finish_sessions_to_replace_device(clock, &browser_session.user, &device)
        .await?;

    let session_counts = count_user_sessions_for_limiting(repo, &browser_session.user).await?;

    let res = policy
        .evaluate_compat_login(mas_policy::CompatLoginInput {
            user: &browser_session.user,
            login: CompatLogin::Token,
            session_replaced,
            session_counts,
            requester,
        })
        .await?;
    process_violations_for_compat_login(
        clock,
        repo,
        session_limit_config,
        &browser_session.user,
        res.violations,
    )
    .await?;

    // We first create the session in the database, commit the transaction, then
    // create it on the homeserver, scheduling a device sync job afterwards to
    // make sure we don't end up in an inconsistent state.
    let compat_session = repo
        .compat_session()
        .add(
            rng,
            clock,
            &browser_session.user,
            device,
            Some(&browser_session),
            false,
            initial_device_display_name,
        )
        .await?;

    repo.compat_sso_login()
        .exchange(clock, login, &compat_session)
        .await?;

    Ok((compat_session, browser_session.user))
}

async fn user_password_login(
    mut rng: &mut (impl RngCore + CryptoRng + Send),
    clock: &impl Clock,
    password_manager: &PasswordManager,
    limiter: &Limiter,
    requester: RequesterFingerprint,
    repo: &mut BoxRepository,
    policy: &mut Policy,
    policy_requester: Requester,
    session_limit_config: Option<&SessionLimitConfig>,
    username: &str,
    password: String,
    requested_device_id: Option<String>,
    initial_device_display_name: Option<String>,
) -> Result<(CompatSession, User), RouteError> {
    // Find the user
    let user = repo
        .user()
        .find_by_username(username)
        .await?
        .filter(|user| user.deactivated_at.is_none())
        .ok_or(RouteError::UserNotFound)?;

    if user.locked_at.is_some() {
        return Err(RouteError::UserLocked);
    }

    // Check the rate limit
    limiter.check_password(requester, &user)?;

    // Lookup its password
    let user_password = repo
        .user_password()
        .active(&user)
        .await?
        .ok_or(RouteError::NoPassword)?;

    // Verify the password
    let password = Zeroizing::new(password);

    match password_manager
        .verify_and_upgrade(
            &mut rng,
            user_password.version,
            password,
            user_password.hashed_password.clone(),
        )
        .await?
    {
        PasswordVerificationResult::Success(Some((version, hashed_password))) => {
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
        PasswordVerificationResult::Success(None) => {}
        PasswordVerificationResult::Failure => {
            return Err(RouteError::PasswordMismatch);
        }
    }

    // We're about to create a device, let's explicitly acquire a lock, so that
    // any concurrent sync will read after we've committed
    repo.user().acquire_lock_for_sync(&user).await?;

    // Now that the user credentials have been verified, start a new compat session
    let device = if let Some(requested_device_id) = requested_device_id {
        Device::from(requested_device_id)
    } else {
        Device::generate(&mut rng)
    };

    let session_replaced = repo
        .app_session()
        .finish_sessions_to_replace_device(clock, &user, &device)
        .await?;

    let session_counts = count_user_sessions_for_limiting(repo, &user).await?;

    let res = policy
        .evaluate_compat_login(mas_policy::CompatLoginInput {
            user: &user,
            login: CompatLogin::Password,
            session_replaced,
            session_counts,
            requester: policy_requester,
        })
        .await?;
    process_violations_for_compat_login(clock, repo, session_limit_config, &user, res.violations)
        .await?;

    let session = repo
        .compat_session()
        .add(
            &mut rng,
            clock,
            &user,
            device,
            None,
            false,
            initial_device_display_name,
        )
        .await?;

    Ok((session, user))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, num::NonZeroU64, ops::Sub};

    use hyper::Request;
    use mas_matrix::{HomeserverConnection, ProvisionRequest};
    use rand::distributions::{Alphanumeric, DistString};
    use sqlx::PgPool;

    use super::*;
    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup, test_site_config};

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

        insta::assert_json_snapshot!(body, @r###"
        {
          "flows": [
            {
              "type": "m.login.password"
            },
            {
              "type": "m.login.sso",
              "oauth_aware_preferred": true,
              "org.matrix.msc3824.delegated_oidc_compatibility": true
            },
            {
              "type": "m.login.token"
            }
          ]
        }
        "###);
    }

    /// Test the cases where the body is invalid
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_bad_body(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // No/empty body
        let request = Request::post("/_matrix/client/v3/login").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r#"
        {
          "errcode": "M_NOT_JSON",
          "error": "Body is not a valid JSON document"
        }
        "#);

        // Missing keys in body
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({}));
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_BAD_JSON",
          "error": "JSON fields are not valid"
        }
        "###);

        // Invalid JSON
        let request = Request::post("/_matrix/client/v3/login")
            .header("Content-Type", "application/json")
            .body("{".to_owned())
            .unwrap();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_NOT_JSON",
          "error": "Body is not a valid JSON document"
        }
        "###);
    }

    /// Test that the server doesn't allow login with a password if the password
    /// manager is disabled
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_disabled(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_login_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        // Now let's get the login flows
        let request = Request::get("/_matrix/client/v3/login").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        insta::assert_json_snapshot!(body, @r###"
        {
          "flows": [
            {
              "type": "m.login.sso",
              "oauth_aware_preferred": true,
              "org.matrix.msc3824.delegated_oidc_compatibility": true
            },
            {
              "type": "m.login.token"
            }
          ]
        }
        "###);

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
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_UNKNOWN",
          "error": "Invalid login type"
        }
        "###);
    }

    async fn user_with_password(
        state: &TestState,
        username: &str,
        password: &str,
        locked: bool,
    ) -> User {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.to_owned())
            .await
            .unwrap();
        let (version, hash) = state
            .password_manager
            .hash(&mut rng, Zeroizing::new(password.to_owned()))
            .await
            .unwrap();

        repo.user_password()
            .add(&mut rng, &state.clock, &user, version, hash, None)
            .await
            .unwrap();
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub, locked))
            .await
            .unwrap();

        let user = if locked {
            repo.user().lock(&state.clock, user).await.unwrap()
        } else {
            user
        };

        repo.save().await.unwrap();
        user
    }

    /// Test that a user can login with a password using the Matrix
    /// compatibility API.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_user_password_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let user = user_with_password(&state, "alice", "password", true).await;

        // Now let's try to login with the password, without asking for a refresh token.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));

        // First try to login to a locked account
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_USER_LOCKED",
          "error": "User account has been locked"
        }
        "###);

        // Now try again after unlocking the account
        let mut repo = state.repository().await.unwrap();
        let user = repo.user().unlock(user).await.unwrap();
        repo.save().await.unwrap();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "access_token": "mct_cxG6gZXyvelQWW9XqfNbm5KAQovodf_XvJz43",
          "device_id": "42oTpLoieH",
          "user_id": "@alice:example.com"
        }
        "###);

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

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "access_token": "mct_PGMLvvMXC4Ds1A3lCWc6Hx4l9DGzqG_lVEIV2",
          "device_id": "Yp7FM44zJN",
          "user_id": "@alice:example.com",
          "refresh_token": "mcr_LoYqtrtBUBcWlE4RX6o47chBCGkadB_9gzpc1",
          "expires_in_ms": 300000
        }
        "###);

        // Try logging in with the 'user' property
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "user": "alice",
            "password": "password",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "access_token": "mct_Xl3bbpfh9yNy9NzuRxyR3b3PLW0rqd_DiXAH2",
          "device_id": "6cq7FqNSYo",
          "user_id": "@alice:example.com"
        }
        "###);

        // Reset the state, to reset rate limits
        let state = state.reset().await;

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
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_FORBIDDEN",
          "error": "Invalid username/password"
        }
        "###);

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

        // Try to login to a deactivated account
        let mut repo = state.repository().await.unwrap();
        let user = repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));

        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_FORBIDDEN",
          "error": "Invalid username/password"
        }
        "###);

        // Should get the same error if the deactivated user is also locked
        let mut repo = state.repository().await.unwrap();
        let _user = repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_FORBIDDEN",
          "error": "Invalid username/password"
        }
        "###);
    }

    /// Test that we can send a login request without a Content-Type header
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_no_content_type(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        user_with_password(&state, "alice", "password", false).await;
        // Try without a Content-Type header
        let mut request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));
        request.headers_mut().remove(hyper::header::CONTENT_TYPE);

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "access_token": "mct_16tugBE5Ta9LIWoSJaAEHHq2g3fx8S_alcBB4",
          "device_id": "ZGpSvYQqlq",
          "user_id": "@alice:example.com"
        }
        "###);
    }

    /// Test that a user can login with a password using the Matrix
    /// compatibility API, using a MXID as identifier
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_user_password_login_mxid(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let user = user_with_password(&state, "alice", "password", true).await;

        // Login with a full MXID as identifier
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "@alice:example.com",
            },
            "password": "password",
        }));

        // First try to login to a locked account
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_USER_LOCKED",
          "error": "User account has been locked"
        }
        "###);

        // Now try again after unlocking the account
        let mut repo = state.repository().await.unwrap();
        let _ = repo.user().unlock(user).await.unwrap();
        repo.save().await.unwrap();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "access_token": "mct_cxG6gZXyvelQWW9XqfNbm5KAQovodf_XvJz43",
          "device_id": "42oTpLoieH",
          "user_id": "@alice:example.com"
        }
        "###);

        // With a MXID, but with the wrong server name
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "@alice:something.corp",
            },
            "password": "password",
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_FORBIDDEN",
          "error": "Invalid username/password"
        }
        "###);
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

        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub, false))
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
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_LIMIT_EXCEEDED",
          "error": "Too many login attempts"
        }
        "###);
    }

    /// Test the response of an unsupported password identifier.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unsupported_login_identifier(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Try to login with an unsupported login flow.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.email",
                "user": "user@example.com"
            },
            "password": "password"
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_UNKNOWN",
          "error": "Unsupported login identifier"
        }
        "###);
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
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_UNKNOWN",
          "error": "Invalid login type"
        }
        "###);
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
        // Start with a locked account
        let user = repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub, false))
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
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_FORBIDDEN",
          "error": "Invalid login token"
        }
        "###);

        let token = get_login_token(&state, &user).await;

        // Try to login with the token.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": token,
        }));
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_USER_LOCKED",
          "error": "User account has been locked"
        }
        "###);

        // Now try again after unlocking the account
        let mut repo = state.repository().await.unwrap();
        let user = repo.user().unlock(user).await.unwrap();
        repo.save().await.unwrap();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "access_token": "mct_bUTa4XIh92RARTPTjqQrCZLAkq2ild_0VsYE6",
          "device_id": "uihy4bk51g",
          "user_id": "@alice:example.com"
        }
        "#);

        // Try again with the same token, it should fail.
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": token,
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_FORBIDDEN",
          "error": "Invalid login token"
        }
        "###);

        // Try to login, but wait too long before sending the request.
        let token = get_login_token(&state, &user).await;

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
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_FORBIDDEN",
          "error": "Login token expired"
        }
        "###);

        // Try to login to a deactivated account
        let token = get_login_token(&state, &user).await;

        let mut repo = state.repository().await.unwrap();
        let user = repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.token",
            "token": token,
        }));
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_FORBIDDEN",
          "error": "Invalid login token"
        }
        "###);

        // Should get the same error if the deactivated user is also locked
        let mut repo = state.repository().await.unwrap();
        let _user = repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "errcode": "M_FORBIDDEN",
          "error": "Invalid login token"
        }
        "###);
    }

    /// Get a login token for a user.
    /// Returns the device and the token.
    ///
    /// # Panics
    ///
    /// Panics if the repository fails.
    async fn get_login_token(state: &TestState, user: &User) -> String {
        // XXX: This is a bit manual, but this is what basically the SSO login flow
        // does.
        let mut repo = state.repository().await.unwrap();

        // Generate a token randomly
        let token = Alphanumeric.sample_string(&mut state.rng(), 32);

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

        // Advance the flow by fulfilling it with a browser session
        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, user, None)
            .await
            .unwrap();
        let _login = repo
            .compat_sso_login()
            .fulfill(&state.clock, login, &browser_session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        token
    }

    /// Test that the `soft_limit` is not enforced for compat login.
    ///
    /// `soft_limit` is for when we allow the user to remove devices in
    /// interactive contexts. With the compatibility login API, there is no
    /// opportunity for us to present a web UI.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_soft_limit_does_not_affect_compat_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                session_limit: Some(SessionLimitConfig {
                    // Lowest non-zero value so we don't have to login a bunch (lower
                    // than `hard_limit`)
                    soft_limit: NonZeroU64::new(1).unwrap(),
                    // Some arbitrary high value (more than we login)
                    hard_limit: NonZeroU64::new(5).unwrap(),
                    hard_limit_eviction: false,
                }),
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let session_limit_config = state
            .site_config
            .session_limit
            .as_ref()
            .expect("Expected `session_limit` configured for this test");

        assert!(
            session_limit_config.soft_limit < session_limit_config.hard_limit,
            "`soft_limit` should be lower than the `hard_limit` so we don't run into `hard_limit` \
            (we're testing the `soft_limit`)",
        );

        let _user = user_with_password(&state, "alice", "password", false).await;

        // Keep logging in to add more sessions, more than the `soft_limit`
        #[allow(clippy::range_plus_one)]
        for _ in 0..(session_limit_config.soft_limit.get() + 1) {
            let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
                "type": "m.login.password",
                "identifier": {
                    "type": "m.id.user",
                    "user": "alice",
                },
                "password": "password",
            }));
            let response = state.request(request.clone()).await;
            response.assert_status(StatusCode::OK);
        }
    }

    /// Test that the `hard_limit` prevents more sessions
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_hard_limit_compat_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                session_limit: Some(SessionLimitConfig {
                    // (doesn't matter)
                    soft_limit: NonZeroU64::new(1).unwrap(),
                    // Lowest non-zero value so we don't have to login a bunch
                    hard_limit: NonZeroU64::new(1).unwrap(),
                    hard_limit_eviction: false,
                }),
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let session_limit_config = state
            .site_config
            .session_limit
            .as_ref()
            .expect("Expected `session_limit` configured for this test");

        let _user = user_with_password(&state, "alice", "password", false).await;

        // Keep logging in to add more sessions, up to the `hard_limit`
        #[allow(clippy::range_plus_one)]
        for _ in 0..session_limit_config.hard_limit.get() {
            let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
                "type": "m.login.password",
                "identifier": {
                    "type": "m.id.user",
                    "user": "alice",
                },
                "password": "password",
            }));
            let response = state.request(request.clone()).await;
            response.assert_status(StatusCode::OK);
        }

        // One more login will tip us over the `hard_limit`
        let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "alice",
            },
            "password": "password",
        }));
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body.get("errcode")
                .expect("Expected errror response to include an `errcode`"),
            "M_FORBIDDEN",
            "Expected `errcode` to be `M_FORBIDDEN`"
        );
    }

    /// Test that the `hard_limit_eviction` will automatically drop old sessions
    /// when we go over the limit
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_hard_limit_eviction_old_compat_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                session_limit: Some(SessionLimitConfig {
                    // (doesn't matter)
                    soft_limit: NonZeroU64::new(1).unwrap(),
                    // Must be at-least 2 when `hard_limit_eviction`
                    hard_limit: NonZeroU64::new(2).unwrap(),
                    // Option under test
                    hard_limit_eviction: true,
                }),
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let session_limit_config = state
            .site_config
            .session_limit
            .as_ref()
            .expect("Expected `session_limit` configured for this test");

        let user = user_with_password(&state, "alice", "password", false).await;

        let mut login_device_ids: Vec<String> = Vec::new();

        // Keep logging in to add more sessions, up to the `hard_limit`. Then `+ 1` for
        // one more login will drop one of our old sessions to make room for the new
        // login
        #[allow(clippy::range_plus_one)]
        for login_index in 0..(session_limit_config.hard_limit.get() + 1) {
            let original_time = state.clock.now();
            // All of the logins except the last one should be in the past
            if login_index <= session_limit_config.hard_limit.get() {
                // Rewind time so the logins appear older than our "inactive" threshold (90
                // days)
                let login_index_i64: i64 = login_index.try_into().unwrap();
                state
                    .clock
                    // Each login is a day earlier
                    .advance(Duration::days(-200 + login_index_i64));
            }

            let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
                "type": "m.login.password",
                "identifier": {
                    "type": "m.id.user",
                    "user": "alice",
                },
                "password": "password",
            }));
            let response = state.request(request.clone()).await;
            response.assert_status(StatusCode::OK);
            let body: serde_json::Value = response.json();
            let device_id = match body
                .get("device_id")
                .expect("Expected successful login response to include `device_id`")
            {
                serde_json::value::Value::String(device_id) => device_id.to_owned(),
                _ => {
                    panic!("Expected `device_id` to be a string")
                }
            };
            login_device_ids.push(device_id);

            // Restore time
            state.clock.advance(original_time - state.clock.now());
        }

        // TODO: How to wait for `last_active_at` to be set?

        // Sanity check that the compat sessions have `last_active_at` set. This is
        // important as `last_active_at` starts out null.
        let mut repo = state.repository().await.unwrap();
        let compat_session_page = repo
            .compat_session()
            .list(
                CompatSessionFilter::new().for_user(&user).active_only(),
                Pagination::first(session_limit_config.hard_limit.get().try_into().unwrap()),
            )
            .await
            .expect("Should be able to list user's compat sessions");
        for edge in compat_session_page.edges {
            let (compat_session, _) = edge.node;
            let last_active_at = compat_session
                .last_active_at
                .expect("We expect compat sessions to have `last_active_at` set for this test");
            assert!(
                last_active_at < (state.clock.now().sub(Duration::days(90))),
                "Expected compat sessions to have a `last_active_at` older than the 90 day 'inactive' threshold"
            );
        }

        // Ensure we still only have two sessions (`session_limit_config.hard_limit`).
        // We're sanity checking across all session types.
        let session_counts = count_user_sessions_for_limiting(&mut repo, &user)
            .await
            .unwrap();
        assert_eq!(
            session_counts.total, 2,
            "Must not have more sessions ({}) than allowed by the `hard_limit` ({}). \
            Expected one of the old sessions to be dropped to make room for the new login",
            session_counts.total, session_limit_config.hard_limit,
        );

        // Also ensure that the newest sessions remain (we dropped the oldest)
        let compat_session_page = repo
            .compat_session()
            .list(
                CompatSessionFilter::new().for_user(&user).active_only(),
                Pagination::first(2),
            )
            .await
            .expect("Should be able to list user's compat sessions");
        let remaining_active_compat_session_device_ids: HashSet<String> = compat_session_page
            .edges
            .iter()
            .map(|a| {
                a.node
                    .0
                    .device
                    .clone()
                    .expect("Expected each login should havea a device")
                    .as_str()
                    .to_owned()
            })
            .collect();

        let most_recent_login_device_ids: HashSet<String> = login_device_ids
            .iter()
            .rev()
            .take(2)
            .map(std::borrow::ToOwned::to_owned)
            .collect();
        // Sanity check our comparison (ensure we're not comparing an empty set)
        assert_eq!(
            most_recent_login_device_ids.len(),
            2,
            "Expected 2 logins for the next comparison"
        );

        // The remaining sessions should be the most recent sessions
        #[allow(clippy::uninlined_format_args)]
        {
            assert!(
                most_recent_login_device_ids.is_subset(&remaining_active_compat_session_device_ids),
                "Expected the 2 remaining active sessions ({:?}) to include the 2 most recent logins ({:?}). (all logins: {:?})",
                remaining_active_compat_session_device_ids,
                most_recent_login_device_ids,
                login_device_ids,
            );
        }
    }

    /// Test that the `hard_limit_eviction` will automatically drop the oldest sessions
    /// when we go over the limit even if all of the sessions are recent.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_hard_limit_eviction_recent_compat_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                session_limit: Some(SessionLimitConfig {
                    // (doesn't matter)
                    soft_limit: NonZeroU64::new(1).unwrap(),
                    // Must be at-least 2 when `hard_limit_eviction`
                    hard_limit: NonZeroU64::new(2).unwrap(),
                    // Option under test
                    hard_limit_eviction: true,
                }),
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let session_limit_config = state
            .site_config
            .session_limit
            .as_ref()
            .expect("Expected `session_limit` configured for this test");

        let user = user_with_password(&state, "alice", "password", false).await;

        let mut login_device_ids: Vec<String> = Vec::new();

        // Keep logging in to add more sessions, up to the `hard_limit`. Then one more
        // login will drop one of our old sessions to make room for the new login
        #[allow(clippy::range_plus_one)]
        for _ in 0..(session_limit_config.hard_limit.get() + 1) {
            let request = Request::post("/_matrix/client/v3/login").json(serde_json::json!({
                "type": "m.login.password",
                "identifier": {
                    "type": "m.id.user",
                    "user": "alice",
                },
                "password": "password",
            }));
            let response = state.request(request.clone()).await;
            response.assert_status(StatusCode::OK);
            let body: serde_json::Value = response.json();
            let device_id = match body
                .get("device_id")
                .expect("Expected successful login response to include `device_id`")
            {
                serde_json::value::Value::String(device_id) => device_id.to_owned(),
                _ => {
                    panic!("Expected `device_id` to be a string")
                }
            };
            login_device_ids.push(device_id);
        }

        // Ensure we still only have two sessions (`session_limit_config.hard_limit`).
        // We're sanity checking across all session types.
        let mut repo = state.repository().await.unwrap();
        let session_counts = count_user_sessions_for_limiting(&mut repo, &user)
            .await
            .unwrap();
        assert_eq!(
            session_counts.total, 2,
            "Must not have more sessions ({}) than allowed by the `hard_limit` ({}). \
            Expected one of the old sessions to be dropped to make room for the new login",
            session_counts.total, session_limit_config.hard_limit,
        );

        // Also ensure that the newest sessions remain (we dropped the oldest)
        let compat_session_page = repo
            .compat_session()
            .list(
                CompatSessionFilter::new().for_user(&user).active_only(),
                Pagination::first(2),
            )
            .await
            .expect("Should be able to list user's compat sessions");
        let remaining_active_compat_session_device_ids: HashSet<String> = compat_session_page
            .edges
            .iter()
            .map(|a| {
                a.node
                    .0
                    .device
                    .clone()
                    .expect("Expected each login should havea a device")
                    .as_str()
                    .to_owned()
            })
            .collect();

        let most_recent_login_device_ids: HashSet<String> = login_device_ids
            .iter()
            .rev()
            .take(2)
            .map(std::borrow::ToOwned::to_owned)
            .collect();
        // Sanity check our comparison (ensure we're not comparing an empty set)
        assert_eq!(
            most_recent_login_device_ids.len(),
            2,
            "Expected 2 logins for the next comparison"
        );

        // The remaining sessions should be the most recent sessions
        #[allow(clippy::uninlined_format_args)]
        {
            assert!(
                most_recent_login_device_ids.is_subset(&remaining_active_compat_session_device_ids),
                "Expected the 2 remaining active sessions ({:?}) to include the 2 most recent logins ({:?}). (all logins: {:?})",
                remaining_active_compat_session_device_ids,
                most_recent_login_device_ids,
                login_device_ids,
            );
        }
    }
}
