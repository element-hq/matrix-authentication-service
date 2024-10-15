// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::SiteConfig;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{
    job::JobRepositoryExt, queue::VerifyEmailJob, user::UserEmailRepository, BoxClock,
    BoxRepository, BoxRng,
};
use mas_templates::{EmailAddContext, ErrorContext, TemplateContext, Templates};
use serde::Deserialize;

use crate::{views::shared::OptionalPostAuthAction, BoundActivityTracker, PreferredLanguage};

#[derive(Deserialize, Debug)]
pub struct EmailForm {
    email: String,
}

#[tracing::instrument(name = "handlers.views.account_email_add.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    if !site_config.email_change_allowed {
        // XXX: this may not be the best error message, it's not translatable
        return Err(FancyError::new(
            ErrorContext::new()
                .with_description("Email change is not allowed".to_owned())
                .with_details("The site configuration does not allow email changes".to_owned()),
        ));
    }

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = EmailAddContext::new()
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_account_add_email(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(name = "handlers.views.account_email_add.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    PreferredLanguage(locale): PreferredLanguage,
    mut policy: Policy,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    Form(form): Form<ProtectedForm<EmailForm>>,
) -> Result<Response, FancyError> {
    let form = cookie_jar.verify_form(&clock, form)?;
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    // XXX: we really should show human readable errors on the form here
    if !site_config.email_change_allowed {
        return Err(FancyError::new(
            ErrorContext::new()
                .with_description("Email change is not allowed".to_owned())
                .with_details("The site configuration does not allow email changes".to_owned()),
        ));
    }

    // Validate the email address
    if form.email.parse::<lettre::Address>().is_err() {
        return Err(anyhow::anyhow!("Invalid email address").into());
    }

    // Run the email policy
    let res = policy.evaluate_email(&form.email).await?;
    if !res.valid() {
        return Err(FancyError::new(
            ErrorContext::new()
                .with_description(format!("Email address {:?} denied by policy", form.email))
                .with_details(format!("{res}")),
        ));
    }

    // Find an existing email address
    let existing_user_email = repo.user_email().find(&session.user, &form.email).await?;
    let user_email = if let Some(user_email) = existing_user_email {
        user_email
    } else {
        repo.user_email()
            .add(&mut rng, &clock, &session.user, form.email)
            .await?
    };

    // If the email was not confirmed, send a confirmation email & redirect to the
    // verify page
    let next = if user_email.confirmed_at.is_none() {
        repo.job()
            .schedule_job(VerifyEmailJob::new(&user_email).with_language(locale.to_string()))
            .await?;

        let next = mas_router::AccountVerifyEmail::new(user_email.id);
        let next = if let Some(action) = query.post_auth_action {
            next.and_then(action)
        } else {
            next
        };

        url_builder.redirect(&next)
    } else {
        query.go_next_or_default(&url_builder, &mas_router::Account::default())
    };

    repo.save().await?;

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    Ok((cookie_jar, next).into_response())
}
