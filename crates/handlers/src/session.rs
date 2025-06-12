// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Utilities for showing proposer HTML fallbacks when the user is logged out,
//! locked or deactivated

use axum::response::{Html, IntoResponse as _, Response};
use mas_axum_utils::{SessionInfoExt, cookies::CookieJar, csrf::CsrfExt};
use mas_data_model::BrowserSession;
use mas_i18n::DataLocale;
use mas_storage::{BoxRepository, Clock, RepositoryError};
use mas_templates::{AccountInactiveContext, TemplateContext, Templates};
use rand::RngCore;
use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum SessionLoadError {
    Template(#[from] mas_templates::TemplateError),
    Repository(#[from] RepositoryError),
}

#[allow(clippy::large_enum_variant)]
pub enum SessionOrFallback {
    MaybeSession {
        cookie_jar: CookieJar,
        maybe_session: Option<BrowserSession>,
    },
    Fallback {
        response: Response,
    },
}

/// Load a session from the cookie jar, or fall back to an HTML error page if
/// the account is locked, deactivated or logged out
pub async fn load_session_or_fallback(
    cookie_jar: CookieJar,
    clock: &impl Clock,
    rng: impl RngCore,
    templates: &Templates,
    locale: &DataLocale,
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

    if session.user.deactivated_at.is_some() {
        // The account is deactivated, show the 'account deactivated' fallback
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
        let ctx = AccountInactiveContext::new(session.user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale.clone());
        let fallback = templates.render_account_deactivated(&ctx)?;
        let response = (cookie_jar, Html(fallback)).into_response();
        return Ok(SessionOrFallback::Fallback { response });
    }

    if session.user.locked_at.is_some() {
        // The account is locked, show the 'account locked' fallback
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
        let ctx = AccountInactiveContext::new(session.user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale.clone());
        let fallback = templates.render_account_locked(&ctx)?;
        let response = (cookie_jar, Html(fallback)).into_response();
        return Ok(SessionOrFallback::Fallback { response });
    }

    if session.finished_at.is_some() {
        // The session has finished, but the browser still has the cookie. This is
        // likely a 'remote' logout, triggered either by an admin or from the
        // user-management UI. In this case, we show the 'account logged out'
        // fallback.
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
        let ctx = AccountInactiveContext::new(session.user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale.clone());
        let fallback = templates.render_account_logged_out(&ctx)?;
        let response = (cookie_jar, Html(fallback)).into_response();
        return Ok(SessionOrFallback::Fallback { response });
    }

    Ok(SessionOrFallback::MaybeSession {
        cookie_jar,
        maybe_session: Some(session),
    })
}
