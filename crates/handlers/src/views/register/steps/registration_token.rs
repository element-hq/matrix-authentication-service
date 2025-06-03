// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context as _;
use axum::{
    Form,
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
};
use mas_axum_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt as _, ProtectedForm},
};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{BoxClock, BoxRepository, BoxRng};
use mas_templates::{
    FieldError, RegisterStepsRegistrationTokenContext, RegisterStepsRegistrationTokenFormField,
    TemplateContext as _, Templates, ToFormState,
};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{PreferredLanguage, views::shared::OptionalPostAuthAction};

#[derive(Deserialize, Serialize)]
pub(crate) struct RegistrationTokenForm {
    #[serde(default)]
    token: String,
}

impl ToFormState for RegistrationTokenForm {
    type Field = mas_templates::RegisterStepsRegistrationTokenFormField;
}

#[tracing::instrument(
    name = "handlers.views.register.steps.registration_token.get",
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

    // If the registration already has a token, skip this step
    if registration.user_registration_token_id.is_some() {
        let destination = mas_router::RegisterDisplayName::new(registration.id);
        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    }

    let ctx = RegisterStepsRegistrationTokenContext::new()
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register_steps_registration_token(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(
    name = "handlers.views.register.steps.registration_token.post",
    fields(user_registration.id = %id),
    skip_all,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    Path(id): Path<Ulid>,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<RegistrationTokenForm>>,
) -> Result<Response, InternalError> {
    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .context("Could not find user registration")
        .map_err(InternalError::from_anyhow)?;

    // If the registration is completed, we can go to the registration destination
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

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    // Validate the token
    let token = form.token.trim();
    if token.is_empty() {
        let ctx = RegisterStepsRegistrationTokenContext::new()
            .with_form_state(form.to_form_state().with_error_on_field(
                RegisterStepsRegistrationTokenFormField::Token,
                FieldError::Required,
            ))
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        return Ok((
            cookie_jar,
            Html(templates.render_register_steps_registration_token(&ctx)?),
        )
            .into_response());
    }

    // Look up the token
    let Some(registration_token) = repo.user_registration_token().find_by_token(token).await?
    else {
        let ctx = RegisterStepsRegistrationTokenContext::new()
            .with_form_state(form.to_form_state().with_error_on_field(
                RegisterStepsRegistrationTokenFormField::Token,
                FieldError::Invalid,
            ))
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        return Ok((
            cookie_jar,
            Html(templates.render_register_steps_registration_token(&ctx)?),
        )
            .into_response());
    };

    // Check if the token is still valid
    if !registration_token.is_valid(clock.now()) {
        tracing::warn!("Registration token isn't valid (expired or already used)");
        let ctx = RegisterStepsRegistrationTokenContext::new()
            .with_form_state(form.to_form_state().with_error_on_field(
                RegisterStepsRegistrationTokenFormField::Token,
                FieldError::Invalid,
            ))
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        return Ok((
            cookie_jar,
            Html(templates.render_register_steps_registration_token(&ctx)?),
        )
            .into_response());
    }

    // Associate the token with the registration
    let registration = repo
        .user_registration()
        .set_registration_token(registration, &registration_token)
        .await?;

    repo.save().await?;

    // Continue to the next step
    let destination = mas_router::RegisterFinish::new(registration.id);
    Ok((cookie_jar, url_builder.redirect(&destination)).into_response())
}
