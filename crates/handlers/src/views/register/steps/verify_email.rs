// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context;
use axum::{
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Response},
};
use mas_axum_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{BoxRepository, RepositoryAccess, user::UserEmailRepository};
use mas_templates::{
    FieldError, RegisterStepsVerifyEmailContext, RegisterStepsVerifyEmailFormField,
    TemplateContext, Templates, ToFormState,
};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{Limiter, PreferredLanguage, views::shared::OptionalPostAuthAction};

#[derive(Serialize, Deserialize, Debug)]
pub struct CodeForm {
    code: String,
}

impl ToFormState for CodeForm {
    type Field = mas_templates::RegisterStepsVerifyEmailFormField;
}

#[tracing::instrument(
    name = "handlers.views.register.steps.verify_email.get",
    fields(user_registration.id = %id),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    Path(id): Path<Ulid>,
    cookie_jar: CookieJar,
) -> Result<Response, InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .context("Could not find user registration")
        .map_err(InternalError::from_anyhow)?;

    // If the registration is completed, we can go to the registration destination
    // XXX: this might not be the right thing to do? Maybe an error page would be
    // better?
    if registration.completed_at.is_some() {
        let post_auth_action: Option<PostAuthAction> = registration
            .post_auth_action
            .map(serde_json::from_value)
            .transpose()?;

        return Ok((
            cookie_jar,
            OptionalPostAuthAction::from(post_auth_action)
                .go_next(&url_builder)
                .into_response(),
        )
            .into_response());
    }

    let email_authentication_id = registration
        .email_authentication_id
        .context("No email authentication started for this registration")
        .map_err(InternalError::from_anyhow)?;
    let email_authentication = repo
        .user_email()
        .lookup_authentication(email_authentication_id)
        .await?
        .context("Could not find email authentication")
        .map_err(InternalError::from_anyhow)?;

    if email_authentication.completed_at.is_some() {
        // XXX: display a better error here
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Email authentication already completed"
        )));
    }

    let ctx = RegisterStepsVerifyEmailContext::new(email_authentication)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register_steps_verify_email(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(
    name = "handlers.views.account_email_verify.post",
    fields(user_email.id = %id),
    skip_all,
)]
pub(crate) async fn post(
    clock: BoxClock,
    mut rng: BoxRng,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(limiter): State<Limiter>,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    Path(id): Path<Ulid>,
    Form(form): Form<ProtectedForm<CodeForm>>,
) -> Result<Response, InternalError> {
    let form = cookie_jar.verify_form(&clock, form)?;

    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .context("Could not find user registration")
        .map_err(InternalError::from_anyhow)?;

    // If the registration is completed, we can go to the registration destination
    // XXX: this might not be the right thing to do? Maybe an error page would be
    // better?
    if registration.completed_at.is_some() {
        let post_auth_action: Option<PostAuthAction> = registration
            .post_auth_action
            .map(serde_json::from_value)
            .transpose()?;

        return Ok((
            cookie_jar,
            OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder),
        )
            .into_response());
    }

    let email_authentication_id = registration
        .email_authentication_id
        .context("No email authentication started for this registration")
        .map_err(InternalError::from_anyhow)?;
    let email_authentication = repo
        .user_email()
        .lookup_authentication(email_authentication_id)
        .await?
        .context("Could not find email authentication")
        .map_err(InternalError::from_anyhow)?;

    if email_authentication.completed_at.is_some() {
        // XXX: display a better error here
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Email authentication already completed"
        )));
    }

    if let Err(e) = limiter.check_email_authentication_attempt(&email_authentication) {
        tracing::warn!(error = &e as &dyn std::error::Error);
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = RegisterStepsVerifyEmailContext::new(email_authentication)
            .with_form_state(
                form.to_form_state()
                    .with_error_on_form(mas_templates::FormError::RateLimitExceeded),
            )
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_register_steps_verify_email(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    let Some(code) = repo
        .user_email()
        .find_authentication_code(&email_authentication, &form.code)
        .await?
    else {
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx =
            RegisterStepsVerifyEmailContext::new(email_authentication)
                .with_form_state(form.to_form_state().with_error_on_field(
                    RegisterStepsVerifyEmailFormField::Code,
                    FieldError::Invalid,
                ))
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

        let content = templates.render_register_steps_verify_email(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    };

    repo.user_email()
        .complete_authentication(&clock, email_authentication, &code)
        .await?;

    repo.save().await?;

    let destination = mas_router::RegisterFinish::new(registration.id);
    return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
}
