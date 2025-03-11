// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context;
use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use hyper::StatusCode;
use mas_axum_utils::{
    FancyError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_router::UrlBuilder;
use mas_storage::{
    BoxClock, BoxRepository, BoxRng,
    user::{BrowserSessionRepository, UserPasswordRepository},
};
use mas_templates::{ReauthContext, TemplateContext, Templates};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::shared::OptionalPostAuthAction;
use crate::{
    BoundActivityTracker, PreferredLanguage, SiteConfig,
    passwords::PasswordManager,
    session::{SessionOrFallback, load_session_or_fallback},
};

#[derive(Deserialize, Debug)]
pub(crate) struct ReauthForm {
    password: String,
}

#[tracing::instrument(name = "handlers.views.reauth.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
    if !site_config.password_login_enabled {
        // XXX: do something better here
        return Ok(url_builder
            .redirect(&mas_router::Account::default())
            .into_response());
    }

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

    let Some(session) = maybe_session else {
        // If there is no session, redirect to the login screen, keeping the
        // PostAuthAction
        let login = mas_router::Login::from(query.post_auth_action);
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = ReauthContext::default();
    let next = query.load_context(&mut repo).await?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_reauth(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(name = "handlers.views.reauth.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(password_manager): State<PasswordManager>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    mut repo: BoxRepository,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<ReauthForm>>,
) -> Result<Response, FancyError> {
    if !site_config.password_login_enabled {
        // XXX: do something better here
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

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

    let Some(session) = maybe_session else {
        // If there is no session, redirect to the login screen, keeping the
        // PostAuthAction
        let login = mas_router::Login::from(query.post_auth_action);
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    // Load the user password
    let user_password = repo
        .user_password()
        .active(&session.user)
        .await?
        .context("User has no password")?;

    let password = Zeroizing::new(form.password.as_bytes().to_vec());

    // TODO: recover from errors
    // Verify the password, and upgrade it on-the-fly if needed
    let new_password_hash = password_manager
        .verify_and_upgrade(
            &mut rng,
            user_password.version,
            password,
            user_password.hashed_password.clone(),
        )
        .await?;

    let user_password = if let Some((version, new_password_hash)) = new_password_hash {
        // Save the upgraded password
        repo.user_password()
            .add(
                &mut rng,
                &clock,
                &session.user,
                version,
                new_password_hash,
                Some(&user_password),
            )
            .await?
    } else {
        user_password
    };

    // Mark the session as authenticated by the password
    repo.browser_session()
        .authenticate_with_password(&mut rng, &clock, &session, &user_password)
        .await?;

    let cookie_jar = cookie_jar.set_session(&session);
    repo.save().await?;

    let reply = query.go_next(&url_builder);
    Ok((cookie_jar, reply).into_response())
}
