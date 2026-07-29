// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Utilities for showing proposer HTML fallbacks when the user is logged out,
//! locked or deactivated

use axum::response::{Html, IntoResponse as _, Response};
use mas_axum_utils::{RecordAsRequester, SessionInfoExt, cookies::CookieJar, csrf::CsrfExt};
use mas_data_model::{BrowserSession, Clock, User};
use mas_i18n::DataLocale;
use mas_policy::model::SessionCounts;
use mas_router::PostAuthAction;
use mas_storage::{
    BoxRepository, RepositoryError, compat::CompatSessionFilter, oauth2::OAuth2SessionFilter,
    personal::PersonalSessionFilter,
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
        let session_info = session_info.mark_session_ended();
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
    })
}
