// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

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
use mas_data_model::{BoxClock, BoxRng};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::BoxRepository;
use mas_templates::{
    FieldError, FormState, RegisterStepsDisplayNameContext, RegisterStepsDisplayNameFormField,
    TemplateContext as _, Templates, ToFormState,
};
use serde::{Deserialize, Serialize};
//:tchap:
use tchap::email_to_display_name;
//:tchap:end
use ulid::Ulid;

use crate::{PreferredLanguage, views::shared::OptionalPostAuthAction};

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum FormAction {
    #[default]
    Set,
    Skip,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DisplayNameForm {
    #[serde(skip_serializing, default)]
    action: FormAction,
    #[serde(default)]
    display_name: String,
}

impl ToFormState for DisplayNameForm {
    type Field = mas_templates::RegisterStepsDisplayNameFormField;
}

#[tracing::instrument(
    name = "handlers.views.register.steps.display_name.get",
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

    //:tchap:
    let mut ctx = RegisterStepsDisplayNameContext::default();

    let post_auth_action: Option<PostAuthAction> = registration
        .post_auth_action
        .clone()
        .map(serde_json::from_value)
        .transpose()?;

    if let Some(PostAuthAction::ContinueAuthorizationGrant { id }) = post_auth_action
        && let Some(login_hint) = repo
            .oauth2_authorization_grant()
            .lookup(id)
            .await?
            .and_then(|grant| grant.login_hint)
    {
        tracing::trace!(
            "ContinueAuthorizationGrant:{:?} login_hint:{:?}",
            id,
            login_hint
        );

        let display_name = email_to_display_name(&login_hint);

        let mut form_state = FormState::default();
        form_state.set_value(
            RegisterStepsDisplayNameFormField::DisplayName,
            Some(display_name),
        );

        ctx = ctx.with_form_state(form_state);
    } else {
        tracing::warn!("Missing login_hint in post_auth_action");
    }

    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    /*
    let ctx = RegisterStepsDisplayNameContext::new()
        .with_csrf(csrf_token.form_value())
        .with_language(locale);
    */
    //:tchap: end

    let content = templates.render_register_steps_display_name(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(
    name = "handlers.views.register.steps.display_name.post",
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
    Form(form): Form<ProtectedForm<DisplayNameForm>>,
) -> Result<Response, InternalError> {
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

    //:tchap:
    let post_auth_action: Option<PostAuthAction> = registration
        .post_auth_action
        .clone()
        .map(serde_json::from_value)
        .transpose()?;

    let mut form: DisplayNameForm = cookie_jar.verify_form(&clock, form)?;

    // Exécute uniquement si on a un login_hint, sinon erreur
    if let Some(PostAuthAction::ContinueAuthorizationGrant { id }) = post_auth_action
        && let Some(login_hint) = repo
            .oauth2_authorization_grant()
            .lookup(id)
            .await?
            .and_then(|grant| grant.login_hint)
    {
        tracing::trace!(
            "ContinueAuthorizationGrant:{:?} login_hint:{:?}",
            id,
            login_hint
        );

        form = DisplayNameForm {
            action: form.action,
            display_name: email_to_display_name(&login_hint),
        };
    } else {
        tracing::warn!("Missing login_hint in post_auth_action");
    }
    //:tchap: end

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let display_name = match form.action {
        FormAction::Set => {
            let display_name = form.display_name.trim();

            if display_name.is_empty() || display_name.len() > 255 {
                let ctx = RegisterStepsDisplayNameContext::new()
                    .with_form_state(form.to_form_state().with_error_on_field(
                        RegisterStepsDisplayNameFormField::DisplayName,
                        FieldError::Invalid,
                    ))
                    .with_csrf(csrf_token.form_value())
                    .with_language(locale);

                return Ok((
                    cookie_jar,
                    Html(templates.render_register_steps_display_name(&ctx)?),
                )
                    .into_response());
            }

            display_name.to_owned()
        }
        FormAction::Skip => {
            // If the user chose to skip, we do the same as Synapse and use the localpart as
            // default display name
            registration.username.clone()
        }
    };

    let registration = repo
        .user_registration()
        .set_display_name(registration, display_name)
        .await?;

    repo.save().await?;

    let destination = mas_router::RegisterFinish::new(registration.id);
    return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
}
