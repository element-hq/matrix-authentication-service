// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use anyhow::Context;
use axum::{
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::{TypedHeader, extract::Query};
use chrono::Duration;
use hyper::StatusCode;
use mas_axum_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, Clock, MatrixUser};
use mas_matrix::HomeserverConnection;
use mas_policy::{Policy, model::CompatLogin};
use mas_router::{CompatLoginSsoAction, UrlBuilder};
use mas_storage::{BoxRepository, RepositoryAccess, compat::CompatSsoLoginRepository};
use mas_templates::{
    CompatLoginPolicyViolationContext, CompatSsoContext, ErrorContext, TemplateContext, Templates,
};
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    BoundActivityTracker, PreferredLanguage,
    session::{SessionOrFallback, count_user_sessions_for_limiting, load_session_or_fallback},
};

#[derive(Debug, Deserialize)]
pub struct Params {
    action: Option<CompatLoginSsoAction>,
}

#[tracing::instrument(
    name = "handlers.compat.login_sso_complete.get",
    fields(compat_sso_login.id = %id),
    skip_all,
)]
pub async fn get(
    PreferredLanguage(locale): PreferredLanguage,
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    mut policy: Policy,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
    Query(params): Query<Params>,
) -> Result<Response, InternalError> {
    let user_agent = user_agent.map(|ua| ua.to_string());

    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &clock, &mut rng, &templates, &locale, &mut repo,
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

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let Some(session) = maybe_session else {
        // If there is no session, redirect to the login or register screen
        let url = match params.action {
            Some(CompatLoginSsoAction::Register) => {
                url_builder.redirect(&mas_router::Register::and_continue_compat_sso_login(id))
            }
            Some(CompatLoginSsoAction::Login | CompatLoginSsoAction::Unknown) | None => {
                url_builder.redirect(&mas_router::Login::and_continue_compat_sso_login(id))
            }
        };

        return Ok((cookie_jar, url).into_response());
    };

    let login = repo
        .compat_sso_login()
        .lookup(id)
        .await?
        .context("Could not find compat SSO login")
        .map_err(InternalError::from_anyhow)?;

    // Bail out if that login session is more than 30min old
    if clock.now() > login.created_at + Duration::microseconds(30 * 60 * 1000 * 1000) {
        let ctx = ErrorContext::new()
            .with_code("compat_sso_login_expired")
            .with_description("This login session expired.".to_owned())
            .with_language(&locale);

        let content = templates.render_error(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    // We can close the repository early, we don't need it at this point
    repo.save().await?;

    let res = policy
        .evaluate_compat_login(mas_policy::CompatLoginInput {
            user: &session.user,
            login: CompatLogin::Sso {
                redirect_uri: login.redirect_uri.to_string(),
            },
            // We don't know if there's going to be a replacement until we received the device ID,
            // which happens too late.
            session_replaced: false,
            session_counts,
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;
    if !res.valid() {
        let ctx = CompatLoginPolicyViolationContext::for_violations(res.violations)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_compat_login_policy_violation(&ctx)?;

        return Ok((StatusCode::FORBIDDEN, cookie_jar, Html(content)).into_response());
    }

    // Fetch informations about the user. This is purely cosmetic, so we let it
    // fail and put a 1s timeout to it in case we fail to query it
    // XXX: we're likely to need this in other places
    let localpart = &session.user.username;
    let display_name = match tokio::time::timeout(
        std::time::Duration::from_secs(1),
        homeserver.query_user(localpart),
    )
    .await
    {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                localpart,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(localpart, "Timed out while querying user");
            None
        }
    };

    let matrix_user = MatrixUser {
        mxid: homeserver.mxid(localpart),
        display_name,
    };

    let ctx = CompatSsoContext::new(login, matrix_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_sso_login(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(
    name = "handlers.compat.login_sso_complete.post",
    fields(compat_sso_login.id = %id),
    skip_all,
)]
pub async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    mut policy: Policy,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
    Query(params): Query<Params>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<Response, InternalError> {
    let user_agent = user_agent.map(|ua| ua.to_string());

    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &clock, &mut rng, &templates, &locale, &mut repo,
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

    cookie_jar.verify_form(&clock, form)?;

    let Some(session) = maybe_session else {
        // If there is no session, redirect to the login or register screen
        let url = match params.action {
            Some(CompatLoginSsoAction::Register) => {
                url_builder.redirect(&mas_router::Register::and_continue_compat_sso_login(id))
            }
            Some(CompatLoginSsoAction::Login | CompatLoginSsoAction::Unknown) | None => {
                url_builder.redirect(&mas_router::Login::and_continue_compat_sso_login(id))
            }
        };

        return Ok((cookie_jar, url).into_response());
    };

    let login = repo
        .compat_sso_login()
        .lookup(id)
        .await?
        .context("Could not find compat SSO login")
        .map_err(InternalError::from_anyhow)?;

    // Bail out if that login session isn't pending, or is more than 30min old
    if !login.is_pending()
        || clock.now() > login.created_at + Duration::microseconds(30 * 60 * 1000 * 1000)
    {
        let ctx = ErrorContext::new()
            .with_code("compat_sso_login_expired")
            .with_description("This login session expired.".to_owned())
            .with_language(&locale);

        let content = templates.render_error(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    let redirect_uri = {
        let mut redirect_uri = login.redirect_uri.clone();
        redirect_uri
            .query_pairs_mut()
            .append_pair("loginToken", &login.login_token);
        redirect_uri
    };

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    let res = policy
        .evaluate_compat_login(mas_policy::CompatLoginInput {
            user: &session.user,
            login: CompatLogin::Sso {
                redirect_uri: login.redirect_uri.to_string(),
            },
            session_counts,
            // We don't know if there's going to be a replacement until we received the device ID,
            // which happens too late.
            session_replaced: false,
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;

    if !res.valid() {
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = CompatLoginPolicyViolationContext::for_violations(res.violations)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_compat_login_policy_violation(&ctx)?;

        return Ok((StatusCode::FORBIDDEN, cookie_jar, Html(content)).into_response());
    }

    // Note that if the login is not Pending,
    // this fails and aborts the transaction.
    repo.compat_sso_login()
        .fulfill(&clock, login, &session)
        .await?;

    repo.save().await?;

    Ok((cookie_jar, Redirect::to(redirect_uri.as_str())).into_response())
}
