// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::str::FromStr;

use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::typed_header::TypedHeader;
use lettre::Address;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::{SiteConfig, UserAgent};
use mas_router::UrlBuilder;
use mas_storage::{
    job::JobRepositoryExt, queue::SendAccountRecoveryEmailsJob, BoxClock, BoxRepository, BoxRng,
};
use mas_templates::{
    EmptyContext, FieldError, FormError, FormState, RecoveryStartContext, RecoveryStartFormField,
    TemplateContext, Templates,
};
use serde::{Deserialize, Serialize};

use crate::{BoundActivityTracker, Limiter, PreferredLanguage, RequesterFingerprint};

#[derive(Deserialize, Serialize)]
pub(crate) struct StartRecoveryForm {
    email: String,
}

pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
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

    let context = RecoveryStartContext::new()
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    repo.save().await?;

    let rendered = templates.render_recovery_start(&context)?;

    Ok((cookie_jar, Html(rendered)).into_response())
}

pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    user_agent: TypedHeader<headers::UserAgent>,
    activity_tracker: BoundActivityTracker,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    (State(limiter), requester): (State<Limiter>, RequesterFingerprint),
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<StartRecoveryForm>>,
) -> Result<impl IntoResponse, FancyError> {
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

    let user_agent = UserAgent::parse(user_agent.as_str().to_owned());
    let ip_address = activity_tracker.ip();

    let form = cookie_jar.verify_form(&clock, form)?;
    let mut form_state = FormState::from_form(&form);

    if Address::from_str(&form.email).is_err() {
        form_state =
            form_state.with_error_on_field(RecoveryStartFormField::Email, FieldError::Invalid);
    }

    if form_state.is_valid() {
        // Check the rate limit if we are about to process the form
        if let Err(e) = limiter.check_account_recovery(requester, &form.email) {
            tracing::warn!(error = &e as &dyn std::error::Error);
            form_state.add_error_on_form(FormError::RateLimitExceeded);
        }
    }

    if !form_state.is_valid() {
        repo.save().await?;
        let context = RecoveryStartContext::new()
            .with_form_state(form_state)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let rendered = templates.render_recovery_start(&context)?;

        return Ok((cookie_jar, Html(rendered)).into_response());
    }

    let session = repo
        .user_recovery()
        .add_session(
            &mut rng,
            &clock,
            form.email,
            user_agent,
            ip_address,
            locale.to_string(),
        )
        .await?;

    repo.job()
        .schedule_job(SendAccountRecoveryEmailsJob::new(&session))
        .await?;

    repo.save().await?;

    Ok((
        cookie_jar,
        url_builder.redirect(&mas_router::AccountRecoveryProgress::new(session.id)),
    )
        .into_response())
}
