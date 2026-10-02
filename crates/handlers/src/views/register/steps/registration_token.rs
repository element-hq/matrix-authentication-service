// Copyright 2025, 2026 Element Creations Ltd.
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

    let email = match registration.email_authentication_id {
        Some(email_authentication_id) => Some(
            repo.user_email()
                .lookup_authentication(email_authentication_id)
                .await?
                .context("Could not load the email authentication")
                .map_err(InternalError::from_anyhow)?
                .email,
        ),
        None => None,
    };

    if !super::token_fits(&registration_token, &registration, email.as_deref()) {
        tracing::warn!("Registration token doesn't fit the registration");
        let ctx = RegisterStepsRegistrationTokenContext::new()
            .with_form_state(form.to_form_state().with_error_on_field(
                RegisterStepsRegistrationTokenFormField::Token,
                FieldError::Mismatch,
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

#[cfg(test)]
mod tests {
    use hyper::{Request, Response, StatusCode, header::LOCATION};
    use mas_data_model::UserRegistration;
    use mas_router::Route as _;
    use sqlx::PgPool;

    use crate::{
        test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup},
        views::register::tests::{
            add_registration, add_registration_token, link_upstream, mint_csrf_token,
        },
    };

    async fn submit_token(
        state: &TestState,
        cookies: &CookieHelper,
        registration: &UserRegistration,
        token: &str,
    ) -> Response<String> {
        let csrf_token = mint_csrf_token(state, cookies);
        let request =
            Request::post(&*mas_router::RegisterToken::new(registration.id).path_and_query())
                .form(serde_json::json!({ "csrf": csrf_token, "token": token }));
        state.request(cookies.with_cookies(request)).await
    }

    /// Assert that the token step refused the token as not fitting the
    /// registration, and attached nothing
    async fn assert_refused(
        state: &TestState,
        response: &Response<String>,
        registration: &UserRegistration,
    ) {
        response.assert_status(StatusCode::OK);
        assert!(
            response.body().contains(r#"data-error-kind="mismatch""#),
            "response body: {}",
            response.body()
        );

        let mut repo = state.repository().await.unwrap();
        let registration = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(registration.user_registration_token_id, None);
    }

    /// The token step comes before the email address is verified
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_accepts_token_pinning_an_unverified_email(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        add_registration_token(
            &state,
            "invite_alice",
            Some("alice"),
            Some("alice@example.com"),
            false,
        )
        .await;
        let registration = add_registration(&state, &cookies, "alice", None, true, None).await;

        let mut repo = state.repository().await.unwrap();
        let authentication = repo
            .user_email()
            .add_authentication_for_registration(
                &mut state.rng(),
                &state.clock,
                "alice@example.com".to_owned(),
                &registration,
            )
            .await
            .unwrap();
        let registration = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let response = submit_token(&state, &cookies, &registration, "invite_alice").await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(
            LOCATION,
            &mas_router::RegisterFinish::new(registration.id).path_and_query(),
        );
    }

    /// A registration linked upstream needs no password, so any token fits it
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_accepts_token_not_passwordless_upstream(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        add_registration_token(&state, "plain", None, None, false).await;
        let registration = add_registration(
            &state,
            &cookies,
            "alice",
            Some("alice@example.com"),
            false,
            None,
        )
        .await;
        let registration = link_upstream(&state, registration).await;

        let response = submit_token(&state, &cookies, &registration, "plain").await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(
            LOCATION,
            &mas_router::RegisterFinish::new(registration.id).path_and_query(),
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_refuses_token_pinning_another_username(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        add_registration_token(&state, "invite_alice", Some("alice"), None, false).await;
        let registration = add_registration(
            &state,
            &cookies,
            "mallory",
            Some("mallory@example.com"),
            true,
            None,
        )
        .await;

        let response = submit_token(&state, &cookies, &registration, "invite_alice").await;
        assert_refused(&state, &response, &registration).await;
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_refuses_token_pinning_another_email(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        add_registration_token(
            &state,
            "invite_alice",
            None,
            Some("alice@example.com"),
            false,
        )
        .await;

        let registration = add_registration(
            &state,
            &cookies,
            "mallory",
            Some("mallory@example.com"),
            true,
            None,
        )
        .await;
        let response = submit_token(&state, &cookies, &registration, "invite_alice").await;
        assert_refused(&state, &response, &registration).await;

        // Nor does it fit a registration without an email address
        let registration = add_registration(&state, &cookies, "bob", None, true, None).await;
        let response = submit_token(&state, &cookies, &registration, "invite_alice").await;
        assert_refused(&state, &response, &registration).await;
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_refuses_token_not_passwordless_without_password(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        add_registration_token(&state, "plain", None, None, false).await;
        let registration = add_registration(
            &state,
            &cookies,
            "alice",
            Some("alice@example.com"),
            false,
            None,
        )
        .await;

        let response = submit_token(&state, &cookies, &registration, "plain").await;
        assert_refused(&state, &response, &registration).await;
    }
}
