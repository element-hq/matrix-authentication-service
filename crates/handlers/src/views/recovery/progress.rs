// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use hyper::StatusCode;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::SiteConfig;
use mas_router::UrlBuilder;
use mas_storage::{
    job::JobRepositoryExt, queue::SendAccountRecoveryEmailsJob, BoxClock, BoxRepository, BoxRng,
};
use mas_templates::{EmptyContext, RecoveryProgressContext, TemplateContext, Templates};
use ulid::Ulid;

use crate::{Limiter, PreferredLanguage, RequesterFingerprint};

pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
) -> Result<Response, FancyError> {
    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_session(&mut repo).await?;
    if maybe_session.is_some() {
        // TODO: redirect to continue whatever action was going on
        return Ok((cookie_jar, url_builder.redirect(&mas_router::Index)).into_response());
    }

    let Some(recovery_session) = repo.user_recovery().lookup_session(id).await? else {
        // XXX: is that the right thing to do?
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::AccountRecoveryStart),
        )
            .into_response());
    };

    if recovery_session.consumed_at.is_some() {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_consumed(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let context = RecoveryProgressContext::new(recovery_session, false)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    repo.save().await?;

    let rendered = templates.render_recovery_progress(&context)?;

    Ok((cookie_jar, Html(rendered)).into_response())
}

pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    (State(limiter), requester): (State<Limiter>, RequesterFingerprint),
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<Response, FancyError> {
    if !site_config.account_recovery_allowed {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_disabled(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let maybe_session = session_info.load_session(&mut repo).await?;
    if maybe_session.is_some() {
        // TODO: redirect to continue whatever action was going on
        return Ok((cookie_jar, url_builder.redirect(&mas_router::Index)).into_response());
    }

    let Some(recovery_session) = repo.user_recovery().lookup_session(id).await? else {
        // XXX: is that the right thing to do?
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::AccountRecoveryStart),
        )
            .into_response());
    };

    if recovery_session.consumed_at.is_some() {
        let context = EmptyContext.with_language(locale);
        let rendered = templates.render_recovery_consumed(&context)?;
        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    // Verify the CSRF token
    let () = cookie_jar.verify_form(&clock, form)?;

    // Check the rate limit if we are about to process the form
    if let Err(e) = limiter.check_account_recovery(requester, &recovery_session.email) {
        tracing::warn!(error = &e as &dyn std::error::Error);
        let context = RecoveryProgressContext::new(recovery_session, true)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);
        let rendered = templates.render_recovery_progress(&context)?;

        return Ok((StatusCode::TOO_MANY_REQUESTS, (cookie_jar, Html(rendered))).into_response());
    }

    // Schedule a new batch of emails
    repo.job()
        .schedule_job(SendAccountRecoveryEmailsJob::new(&recovery_session))
        .await?;

    repo.save().await?;

    let context = RecoveryProgressContext::new(recovery_session, false)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let rendered = templates.render_recovery_progress(&context)?;

    Ok((cookie_jar, Html(rendered)).into_response())
}
