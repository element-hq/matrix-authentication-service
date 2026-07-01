// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use axum_extra::{extract::Query, typed_header::TypedHeader};
use mas_axum_utils::{InternalError, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng};
use mas_keystore::Keystore;
use mas_matrix::HomeserverConnection;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{BoxRepository, user::LoginSessionRepository};
use mas_templates::{AppContext, TemplateContext, Templates};
use serde::Deserialize;

use crate::{
    BoundActivityTracker, PreferredLanguage,
    oauth2::authorization::id_token_hint::{
        resolve_id_token_hint, session_matches_requested_identity,
    },
    session::{SessionOrFallback, load_session_or_fallback},
};

#[derive(Deserialize)]
pub struct Params {
    #[serde(default, flatten)]
    action: Option<mas_router::AccountAction>,

    #[serde(rename = "org.matrix.msc4198.login_hint")]
    unstable_login_hint: Option<String>,

    // XXX: MSC4198 only defines `login_hint`; this uses the same unstable
    // prefix for its trusted sibling pending MSC feedback.
    #[serde(rename = "org.matrix.msc4198.id_token_hint")]
    unstable_id_token_hint: Option<String>,
}

#[tracing::instrument(name = "handlers.views.app.get", skip_all)]
pub async fn get(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(key_store): State<Keystore>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    activity_tracker: BoundActivityTracker,
    State(url_builder): State<UrlBuilder>,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    Query(Params {
        action,
        unstable_login_hint,
        unstable_id_token_hint,
    }): Query<Params>,
    mut repo: BoxRepository,
    clock: BoxClock,
    mut rng: BoxRng,
    cookie_jar: CookieJar,
) -> Result<impl IntoResponse, InternalError> {
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar,
        &clock,
        &mut rng,
        &templates,
        &locale,
        Some(PostAuthAction::manage_account(action.clone())),
        &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => return Ok(response),
    };

    // If the deeplink carries a hint, resolve the requested identity: a
    // verified `id_token_hint` gives a trusted target, a `login_hint` stays
    // an untrusted string. Both get persisted on a login session below, so
    // they survive the multi-hop login flow — the deeplink has no
    // authorization grant to hang them off.
    let resolved_hint = match unstable_id_token_hint.as_deref() {
        Some(raw_hint) => {
            resolve_id_token_hint(&mut repo, &clock, &key_store, &url_builder, raw_hint).await?
        }
        None => None,
    };

    // TODO: keep the full path, not just the action
    let Some(session) = maybe_session else {
        if unstable_login_hint.is_none() && resolved_hint.is_none() {
            // No hint to carry: plain login redirect, as before.
            let url = mas_router::Login::and_then(PostAuthAction::manage_account(action));
            return Ok((cookie_jar, url_builder.redirect(&url)).into_response());
        }

        // Persist the login session carrying the requested identity, and
        // continue it through `/login`.
        let login_session = add_login_session(
            &mut repo,
            &mut rng,
            &clock,
            &activity_tracker,
            user_agent,
            action,
            unstable_login_hint.clone(),
            resolved_hint,
        )
        .await?;
        repo.save().await?;

        let mut url =
            mas_router::Login::and_then(PostAuthAction::continue_login_session(login_session.id));
        if let Some(login_hint) = unstable_login_hint {
            // The untrusted hint additionally pre-fills the login form, as
            // before.
            url = url.with_login_hint(login_hint);
        }

        return Ok((cookie_jar, url_builder.redirect(&url)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // If the requested identity doesn't match the active session, divert to
    // the account-mismatch interstitial before letting the deeplinked action
    // run against the wrong account.
    let matches = session_matches_requested_identity(
        &mut repo,
        homeserver.homeserver(),
        resolved_hint.as_ref().map(|hint| hint.user.id),
        unstable_login_hint.as_deref(),
        &session,
    )
    .await?;

    if !matches {
        let login_session = add_login_session(
            &mut repo,
            &mut rng,
            &clock,
            &activity_tracker,
            user_agent,
            action,
            unstable_login_hint,
            resolved_hint,
        )
        .await?;
        repo.save().await?;

        let destination = mas_router::SelectAccount::new(PostAuthAction::continue_login_session(
            login_session.id,
        ));
        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    }

    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

/// Persist a login session for the account-management deeplink, carrying the
/// requested identity and the action to resume once the flow completes.
async fn add_login_session(
    repo: &mut BoxRepository,
    rng: &mut BoxRng,
    clock: &BoxClock,
    activity_tracker: &BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    action: Option<mas_router::AccountAction>,
    login_hint: Option<String>,
    resolved_hint: Option<crate::oauth2::authorization::id_token_hint::ResolvedHint>,
) -> Result<mas_data_model::LoginSession, InternalError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    let post_auth_action = serde_json::to_value(PostAuthAction::manage_account(action))?;
    let (target_user, target_user_session) = match resolved_hint {
        Some(hint) => (Some(hint.user), hint.browser_session),
        None => (None, None),
    };

    let login_session = repo
        .login_session()
        .add(
            rng,
            clock,
            activity_tracker.ip(),
            user_agent,
            Some(post_auth_action),
            login_hint,
            target_user.as_ref(),
            target_user_session.as_ref(),
        )
        .await?;

    Ok(login_session)
}

/// Like `get`, but allow anonymous access.
/// Used for a subset of the account management paths.
/// Needed for e.g. account recovery.
#[tracing::instrument(name = "handlers.views.app.get_anonymous", skip_all)]
pub async fn get_anonymous(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
) -> Result<impl IntoResponse, InternalError> {
    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok(Html(content).into_response())
}
