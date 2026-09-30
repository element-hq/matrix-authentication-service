// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Utilities for showing proposer HTML fallbacks when the user is logged out,
//! locked or deactivated

use std::collections::HashMap;

use axum::response::{Html, IntoResponse as _, Response};
use chrono::Duration;
use mas_axum_utils::{RecordAsRequester, SessionInfoExt, cookies::CookieJar, csrf::CsrfExt};
use mas_data_model::{BrowserSession, Client, Clock, Session, SessionLimitConfig, User};
use mas_i18n::DataLocale;
use mas_policy::model::SessionCounts;
use mas_router::PostAuthAction;
use mas_storage::{
    BoxRepository, Pagination, RepositoryError, compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter, personal::PersonalSessionFilter,
};
use mas_templates::{AccountInactiveContext, TemplateContext, Templates};
use rand::RngCore;
use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum SessionLoadError {
    Template(#[from] mas_templates::TemplateError),
    Repository(#[from] RepositoryError),
}

#[expect(clippy::large_enum_variant)]
pub enum SessionOrFallback {
    MaybeSession {
        cookie_jar: CookieJar,
        maybe_session: Option<BrowserSession>,
    },
    Fallback {
        response: Response,
    },
}

/// Render the right account-inactive interstitial for the given user, carrying
/// the `PostAuthAction` continuation so the sign-out/sign-in button on the page
/// round-trips it through `POST /logout`.
///
/// The template is picked from the user's state: deactivated and locked users
/// get the matching page, otherwise (a still-valid user whose session was
/// finished out-of-band) the 'logged out' page. Call sites should use this
/// rather than building an [`AccountInactiveContext`] themselves, so the
/// continuation action can't be silently dropped.
///
/// Returns the updated cookie jar (with a freshly-minted CSRF token) alongside
/// the rendered response body, so callers can combine them however their own
/// return type requires.
///
/// # Errors
///
/// Returns [`SessionLoadError`] if the template fails to render.
pub fn render_account_inactive(
    templates: &Templates,
    locale: &DataLocale,
    clock: &impl Clock,
    rng: impl RngCore,
    cookie_jar: CookieJar,
    user: User,
    action: Option<PostAuthAction>,
) -> Result<(CookieJar, Response), SessionLoadError> {
    let deactivated = user.deactivated_at.is_some();
    let locked = user.locked_at.is_some();

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
    let ctx = AccountInactiveContext::new(user)
        .with_post_auth_action(action)
        .with_csrf(csrf_token.form_value())
        .with_language(*locale);

    let fallback = if deactivated {
        templates.render_account_deactivated(&ctx)?
    } else if locked {
        templates.render_account_locked(&ctx)?
    } else {
        templates.render_account_logged_out(&ctx)?
    };

    Ok((cookie_jar, Html(fallback).into_response()))
}

/// Load a session from the cookie jar, or fall back to an HTML error page if
/// the account is locked, deactivated or logged out.
///
/// When falling back, the given `action` is threaded into the interstitial so
/// the sign-out/sign-in button preserves the continuation context.
pub async fn load_session_or_fallback(
    cookie_jar: CookieJar,
    clock: &impl Clock,
    rng: impl RngCore,
    templates: &Templates,
    locale: &DataLocale,
    action: Option<PostAuthAction>,
    repo: &mut BoxRepository,
) -> Result<SessionOrFallback, SessionLoadError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let Some(session_id) = session_info.current_session_id() else {
        return Ok(SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session: None,
        });
    };

    let Some(session) = repo.browser_session().lookup(session_id).await? else {
        // We looked up the session, but it was not found. Still update the cookie
        let session_info = session_info.mark_session_ended(clock.now());
        let cookie_jar = cookie_jar.update_session_info(&session_info);
        return Ok(SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session: None,
        });
    };

    // Record the user as the requester even when we return a fallback page
    // below — the request is still attributable to that user.
    session.maybe_record_as_requester();

    // The account is deactivated or locked, or the session has finished out-of-band
    // (a 'remote' logout triggered by an admin or from the user-management UI). In
    // any of these cases, show the matching account-inactive interstitial.
    if session.user.deactivated_at.is_some()
        || session.user.locked_at.is_some()
        || session.finished_at.is_some()
    {
        let (cookie_jar, response) = render_account_inactive(
            templates,
            locale,
            clock,
            rng,
            cookie_jar,
            session.user,
            action,
        )?;
        let response = (cookie_jar, response).into_response();
        return Ok(SessionOrFallback::Fallback { response });
    }

    Ok(SessionOrFallback::MaybeSession {
        cookie_jar,
        maybe_session: Some(session),
    })
}

/// Get a count of sessions for the given user, for the purposes of session
/// limiting.
///
/// Includes:
/// - OAuth 2 sessions
/// - Compatibility sessions
/// - Personal sessions (unless owned by a different user)
///
/// # Backstory
///
/// Originally, we were only intending to count sessions with devices in this
/// result, because those are the entries that are expensive for Synapse and
/// also would not hinder use of deviceless clients (like Element Admin, an
/// admin dashboard).
///
/// However, to do so, we would need to count only sessions including device
/// scopes. To do this efficiently, we'd need a partial index on sessions
/// including device scopes.
///
/// It turns out that this can't be done cleanly (as we need to, in Postgres,
/// match scope lists where one of the scopes matches one of 2 known prefixes),
/// at least not without somewhat uncomfortable stored functions.
///
/// So for simplicity's sake, we now count all sessions.
/// For practical use cases, it's not likely to make a noticeable difference
/// (and maybe it's good that there's an overall limit).
pub(crate) async fn count_user_sessions_for_limiting(
    repo: &mut BoxRepository,
    user: &User,
) -> Result<SessionCounts, RepositoryError> {
    let oauth2 = repo
        .oauth2_session()
        .count(OAuth2SessionFilter::new().active_only().for_user(user))
        .await? as u64;

    let compat = repo
        .compat_session()
        .count(CompatSessionFilter::new().active_only().for_user(user))
        .await? as u64;

    // Only include self-owned personal sessions, not administratively-owned ones
    let personal = repo
        .personal_session()
        .count(
            PersonalSessionFilter::new()
                .active_only()
                .for_actor_user(user)
                .for_owner_user(user),
        )
        .await? as u64;

    Ok(SessionCounts {
        total: oauth2 + compat + personal,
        oauth2,
        compat,
        personal,
        against_limit: Some(oauth2 + compat + personal),
    })
}

/// Resolved session limits for a login attempt.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResolvedSessionLimit {
    pub rules: mas_data_model::SessionLimitRules,
    /// When true, counts and eviction apply only to this OAuth 2.0 client.
    pub per_client: bool,
}

impl ResolvedSessionLimit {
    pub(crate) fn as_policy_input(self) -> mas_policy::SessionLimitInput {
        self.rules.into()
    }
}

/// Resolve effective session limits for a user, optionally scoped to an OAuth
/// 2.0 client, and count sessions for enforcement.
pub(crate) async fn resolve_session_limit_for_login(
    repo: &mut BoxRepository,
    site_config: &mas_data_model::SiteConfig,
    user: &User,
    client: Option<&mas_data_model::Client>,
) -> Result<(Option<ResolvedSessionLimit>, SessionCounts), RepositoryError> {
    let mut counts = count_user_sessions_for_limiting(repo, user).await?;

    let client_id = client.map(|c| c.id);
    let client_override = if let Some(client_id) = client_id {
        repo.user_session_limit_override()
            .find(user, Some(client_id))
            .await?
    } else {
        None
    };
    let global_override = repo.user_session_limit_override().find(user, None).await?;

    let per_client_config =
        client_id.and_then(|id| site_config.session_limit_per_client.get(&id).copied());
    let global_config = site_config
        .session_limit
        .as_ref()
        .map(SessionLimitConfig::rules);

    let (rules, per_client) = if let Some(ov) = client_override {
        let base =
            per_client_config
                .or(global_config)
                .unwrap_or(mas_data_model::SessionLimitRules {
                    soft_limit: ov.soft_limit,
                    hard_limit: ov.hard_limit,
                    max_session_threshold: None,
                    dangerous_hard_limit_eviction: false,
                });
        (
            mas_data_model::SessionLimitRules {
                soft_limit: ov.soft_limit,
                hard_limit: ov.hard_limit,
                max_session_threshold: base.max_session_threshold,
                dangerous_hard_limit_eviction: base.dangerous_hard_limit_eviction,
            },
            true,
        )
    } else if let Some(rules) = per_client_config {
        (rules, true)
    } else if let Some(ov) = global_override {
        let base = global_config.unwrap_or(mas_data_model::SessionLimitRules {
            soft_limit: ov.soft_limit,
            hard_limit: ov.hard_limit,
            max_session_threshold: None,
            dangerous_hard_limit_eviction: false,
        });
        (
            mas_data_model::SessionLimitRules {
                soft_limit: ov.soft_limit,
                hard_limit: ov.hard_limit,
                max_session_threshold: base.max_session_threshold,
                dangerous_hard_limit_eviction: base.dangerous_hard_limit_eviction,
            },
            false,
        )
    } else if let Some(rules) = global_config {
        (rules, false)
    } else {
        return Ok((None, counts));
    };

    if per_client && let Some(client) = client {
        let oauth2_for_client = repo
            .oauth2_session()
            .count(
                OAuth2SessionFilter::new()
                    .active_only()
                    .for_user(user)
                    .for_client(client),
            )
            .await? as u64;
        counts.against_limit = Some(oauth2_for_client);
    }

    Ok((Some(ResolvedSessionLimit { rules, per_client }), counts))
}

/// Whether a policy result is solely a session-limit violation that should be
/// resolved by LRU eviction instead of refusing the login.
pub(crate) fn session_limit_allows_hard_eviction(
    res: &mas_policy::EvaluationResult,
    resolved: Option<&ResolvedSessionLimit>,
    against_limit: u64,
) -> Option<(ResolvedSessionLimit, u32)> {
    let resolved = *resolved?;
    let [
        mas_policy::Violation {
            variant: Some(mas_policy::ViolationVariant::TooManySessions { need_to_remove }),
            ..
        },
    ] = &res.violations[..]
    else {
        return None;
    };
    if res.valid() {
        return None;
    }
    if !resolved.rules.dangerous_hard_limit_eviction {
        return None;
    }
    if against_limit < resolved.rules.hard_limit.get() {
        return None;
    }
    Some((resolved, *need_to_remove))
}

const INACTIVE_SESSION_THRESHOLD: chrono::TimeDelta = Duration::days(90);
const MINIMUM_SESSIONS_TO_FETCH: usize = 2160;

/// Find LRU active OAuth 2.0 sessions for a user and client.
pub(crate) async fn find_lru_oauth2_sessions_for_client(
    clock: &dyn Clock,
    repo: &mut BoxRepository,
    user: &User,
    client: &Client,
    num_requested: usize,
) -> Result<Vec<Session>, RepositoryError> {
    let mut edges_to_consider = Vec::new();
    let inactive_threshold_date = clock.now() - INACTIVE_SESSION_THRESHOLD;

    let inactive_page = repo
        .oauth2_session()
        .list(
            OAuth2SessionFilter::new()
                .for_user(user)
                .for_client(client)
                .active_only()
                .with_last_active_before(inactive_threshold_date),
            Pagination::first(std::cmp::max(num_requested, MINIMUM_SESSIONS_TO_FETCH)),
        )
        .await?;
    edges_to_consider.extend(inactive_page.edges);

    if edges_to_consider.len() < num_requested {
        let active_page = repo
            .oauth2_session()
            .list(
                OAuth2SessionFilter::new()
                    .for_user(user)
                    .for_client(client)
                    .active_only(),
                Pagination::first(std::cmp::max(num_requested, MINIMUM_SESSIONS_TO_FETCH)),
            )
            .await?;
        edges_to_consider.extend(active_page.edges);
    }

    let mut session_map = HashMap::new();
    for edge in edges_to_consider {
        session_map.insert(edge.node.id, edge.node);
    }

    let mut sessions: Vec<Session> = session_map.into_values().collect();
    sessions.sort_by_key(|session| (session.last_active_at, session.created_at, session.id));
    Ok(sessions)
}

/// Finish the least recently used OAuth 2.0 sessions for a user+client.
///
/// Returns `true` if enough sessions were finished.
pub(crate) async fn evict_lru_oauth2_sessions_for_client(
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    repo: &mut BoxRepository,
    user: &User,
    client: &Client,
    need_to_remove: usize,
) -> Result<bool, RepositoryError> {
    use mas_storage::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};

    let sessions =
        find_lru_oauth2_sessions_for_client(clock, repo, user, client, need_to_remove).await?;
    if sessions.len() < need_to_remove {
        return Ok(false);
    }

    for session in &sessions[0..need_to_remove] {
        tracing::info!(
            user_id = %user.id,
            username = user.username,
            oauth2_session_id = %session.id,
            oauth2_client_id = %client.id,
            "Automatically removing OAuth 2.0 session (`dangerous_hard_limit_eviction`)"
        );
        repo.oauth2_session().finish(clock, session.clone()).await?;
    }

    repo.queue_job()
        .schedule_job(rng, clock, SyncDevicesJob::new_for_id(user.id))
        .await?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, num::NonZeroU64};

    use mas_data_model::{SessionLimitConfig, SessionLimitRules, SiteConfig};
    use oauth2_types::{requests::GrantType, scope::OPENID};
    use sqlx::PgPool;

    use super::*;
    use crate::test_utils::{TestState, setup, test_site_config};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_resolve_session_limit_global_and_override(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                session_limit: Some(SessionLimitConfig {
                    soft_limit: NonZeroU64::new(2).unwrap(),
                    hard_limit: NonZeroU64::new(4).unwrap(),
                    max_session_threshold: None,
                    dangerous_hard_limit_eviction: false,
                }),
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let (resolved, counts) =
            resolve_session_limit_for_login(&mut repo, &state.site_config, &user, None)
                .await
                .unwrap();
        let resolved = resolved.expect("global session_limit should apply");
        assert!(!resolved.per_client);
        assert_eq!(resolved.rules.soft_limit.get(), 2);
        assert_eq!(resolved.rules.hard_limit.get(), 4);
        assert_eq!(counts.against_limit, Some(0));

        repo.user_session_limit_override()
            .add(
                &mut rng,
                &state.clock,
                &user,
                None,
                NonZeroU64::new(9).unwrap(),
                NonZeroU64::new(11).unwrap(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let mut repo = state.repository().await.unwrap();
        let user = repo.user().lookup(user.id).await.unwrap().unwrap();
        let (resolved, _) =
            resolve_session_limit_for_login(&mut repo, &state.site_config, &user, None)
                .await
                .unwrap();
        let resolved = resolved.expect("user override should apply");
        assert!(!resolved.per_client);
        assert_eq!(resolved.rules.soft_limit.get(), 9);
        assert_eq!(resolved.rules.hard_limit.get(), 11);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_resolve_session_limit_per_client(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &state.clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.oauth2_session()
            .add_from_browser_session(
                &mut rng,
                &state.clock,
                &client,
                &browser_session,
                [OPENID].into_iter().collect(),
            )
            .await
            .unwrap();
        let client_id = client.id;
        let user_id = user.id;
        repo.save().await.unwrap();

        state.site_config.session_limit = Some(SessionLimitConfig {
            soft_limit: NonZeroU64::new(32).unwrap(),
            hard_limit: NonZeroU64::new(64).unwrap(),
            max_session_threshold: None,
            dangerous_hard_limit_eviction: false,
        });
        state.site_config.session_limit_per_client = HashMap::from([(
            client_id,
            SessionLimitRules {
                soft_limit: NonZeroU64::new(1).unwrap(),
                hard_limit: NonZeroU64::new(2).unwrap(),
                max_session_threshold: None,
                dangerous_hard_limit_eviction: false,
            },
        )]);

        let mut repo = state.repository().await.unwrap();
        let user = repo.user().lookup(user_id).await.unwrap().unwrap();
        let client = repo
            .oauth2_client()
            .lookup(client_id)
            .await
            .unwrap()
            .unwrap();

        let (resolved, counts) =
            resolve_session_limit_for_login(&mut repo, &state.site_config, &user, Some(&client))
                .await
                .unwrap();
        let resolved = resolved.expect("per-client session_limit should apply");
        assert!(resolved.per_client);
        assert_eq!(resolved.rules.soft_limit.get(), 1);
        assert_eq!(resolved.rules.hard_limit.get(), 2);
        assert_eq!(counts.against_limit, Some(1));
        assert!(counts.total >= 1);

        repo.user_session_limit_override()
            .add(
                &mut rng,
                &state.clock,
                &user,
                Some(client.id),
                NonZeroU64::new(7).unwrap(),
                NonZeroU64::new(8).unwrap(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let mut repo = state.repository().await.unwrap();
        let user = repo.user().lookup(user_id).await.unwrap().unwrap();
        let client = repo
            .oauth2_client()
            .lookup(client_id)
            .await
            .unwrap()
            .unwrap();
        let (resolved, _) =
            resolve_session_limit_for_login(&mut repo, &state.site_config, &user, Some(&client))
                .await
                .unwrap();
        let resolved = resolved.expect("per-client user override should apply");
        assert!(resolved.per_client);
        assert_eq!(resolved.rules.soft_limit.get(), 7);
        assert_eq!(resolved.rules.hard_limit.get(), 8);
    }
}
