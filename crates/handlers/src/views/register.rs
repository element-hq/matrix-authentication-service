// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::str::FromStr;

use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::typed_header::TypedHeader;
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::{CaptchaConfig, UserAgent};
use mas_i18n::DataLocale;
use mas_matrix::BoxHomeserverConnection;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{
    job::JobRepositoryExt,
    queue::{ProvisionUserJob, VerifyEmailJob},
    user::{BrowserSessionRepository, UserEmailRepository, UserPasswordRepository, UserRepository},
    BoxClock, BoxRepository, BoxRng, RepositoryAccess,
};
use mas_templates::{
    FieldError, FormError, RegisterContext, RegisterFormField, TemplateContext, Templates,
    ToFormState,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::shared::OptionalPostAuthAction;
use crate::{
    captcha::Form as CaptchaForm, passwords::PasswordManager, BoundActivityTracker, Limiter,
    PreferredLanguage, RequesterFingerprint, SiteConfig,
};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RegisterForm {
    username: String,
    email: String,
    password: String,
    password_confirm: String,
    #[serde(default)]
    accept_terms: String,

    #[serde(flatten, skip_serializing)]
    captcha: CaptchaForm,
}

impl ToFormState for RegisterForm {
    type Field = RegisterFormField;
}

#[tracing::instrument(name = "handlers.views.register.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    mut repo: BoxRepository,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    if maybe_session.is_some() {
        let reply = query.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    }

    if !site_config.password_registration_enabled {
        // If password-based registration is disabled, redirect to the login page here
        return Ok(url_builder
            .redirect(&mas_router::Login::from(query.post_auth_action))
            .into_response());
    }

    let content = render(
        locale,
        RegisterContext::default(),
        query,
        csrf_token,
        &mut repo,
        &templates,
        site_config.captcha.clone(),
    )
    .await?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(name = "handlers.views.register.post", skip_all, err)]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(password_manager): State<PasswordManager>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    State(homeserver): State<BoxHomeserverConnection>,
    State(http_client): State<reqwest::Client>,
    (State(limiter), requester): (State<Limiter>, RequesterFingerprint),
    mut policy: Policy,
    mut repo: BoxRepository,
    (user_agent, activity_tracker): (
        Option<TypedHeader<headers::UserAgent>>,
        BoundActivityTracker,
    ),
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<RegisterForm>>,
) -> Result<Response, FancyError> {
    let user_agent = user_agent.map(|ua| UserAgent::parse(ua.as_str().to_owned()));
    if !site_config.password_registration_enabled {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    // Validate the captcha
    // TODO: display a nice error message to the user
    let passed_captcha = form
        .captcha
        .verify(
            &activity_tracker,
            &http_client,
            url_builder.public_hostname(),
            site_config.captcha.as_ref(),
        )
        .await
        .is_ok();

    // Validate the form
    let state = {
        let mut state = form.to_form_state();

        if !passed_captcha {
            state.add_error_on_form(FormError::Captcha);
        }

        if form.username.is_empty() {
            state.add_error_on_field(RegisterFormField::Username, FieldError::Required);
        } else if repo.user().exists(&form.username).await? {
            // The user already exists in the database
            state.add_error_on_field(RegisterFormField::Username, FieldError::Exists);
        } else if !homeserver.is_localpart_available(&form.username).await? {
            // The user already exists on the homeserver
            // XXX: we may want to return different errors like "this username is reserved"
            tracing::warn!(
                username = &form.username,
                "User tried to register with a reserved username"
            );

            state.add_error_on_field(RegisterFormField::Username, FieldError::Exists);
        }

        if form.email.is_empty() {
            state.add_error_on_field(RegisterFormField::Email, FieldError::Required);
        } else if Address::from_str(&form.email).is_err() {
            state.add_error_on_field(RegisterFormField::Email, FieldError::Invalid);
        }

        if form.password.is_empty() {
            state.add_error_on_field(RegisterFormField::Password, FieldError::Required);
        }

        if form.password_confirm.is_empty() {
            state.add_error_on_field(RegisterFormField::PasswordConfirm, FieldError::Required);
        }

        if form.password != form.password_confirm {
            state.add_error_on_field(RegisterFormField::Password, FieldError::Unspecified);
            state.add_error_on_field(
                RegisterFormField::PasswordConfirm,
                FieldError::PasswordMismatch,
            );
        }

        if !password_manager.is_password_complex_enough(&form.password)? {
            // TODO localise this error
            state.add_error_on_field(
                RegisterFormField::Password,
                FieldError::Policy {
                    message: "Password is too weak".to_owned(),
                },
            );
        }

        // If the site has terms of service, the user must accept them
        if site_config.tos_uri.is_some() && form.accept_terms != "on" {
            state.add_error_on_field(RegisterFormField::AcceptTerms, FieldError::Required);
        }

        let res = policy
            .evaluate_register(&form.username, &form.email)
            .await?;

        for violation in res.violations {
            match violation.field.as_deref() {
                Some("email") => state.add_error_on_field(
                    RegisterFormField::Email,
                    FieldError::Policy {
                        message: violation.msg,
                    },
                ),
                Some("username") => state.add_error_on_field(
                    RegisterFormField::Username,
                    FieldError::Policy {
                        message: violation.msg,
                    },
                ),
                Some("password") => state.add_error_on_field(
                    RegisterFormField::Password,
                    FieldError::Policy {
                        message: violation.msg,
                    },
                ),
                _ => state.add_error_on_form(FormError::Policy {
                    message: violation.msg,
                }),
            }
        }

        if state.is_valid() {
            // Check the rate limit if we are about to process the form
            if let Err(e) = limiter.check_registration(requester) {
                tracing::warn!(error = &e as &dyn std::error::Error);
                state.add_error_on_form(FormError::RateLimitExceeded);
            }
        }

        state
    };

    if !state.is_valid() {
        let content = render(
            locale,
            RegisterContext::default().with_form_state(state),
            query,
            csrf_token,
            &mut repo,
            &templates,
            site_config.captcha.clone(),
        )
        .await?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    let user = repo.user().add(&mut rng, &clock, form.username).await?;

    if let Some(tos_uri) = &site_config.tos_uri {
        repo.user_terms()
            .accept_terms(&mut rng, &clock, &user, tos_uri.clone())
            .await?;
    }

    let password = Zeroizing::new(form.password.into_bytes());
    let (version, hashed_password) = password_manager.hash(&mut rng, password).await?;
    let user_password = repo
        .user_password()
        .add(&mut rng, &clock, &user, version, hashed_password, None)
        .await?;

    let user_email = repo
        .user_email()
        .add(&mut rng, &clock, &user, form.email)
        .await?;

    let next = mas_router::AccountVerifyEmail::new(user_email.id).and_maybe(query.post_auth_action);

    let session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, user_agent)
        .await?;

    repo.browser_session()
        .authenticate_with_password(&mut rng, &clock, &session, &user_password)
        .await?;

    repo.job()
        .schedule_job(VerifyEmailJob::new(&user_email).with_language(locale.to_string()))
        .await?;

    repo.job()
        .schedule_job(ProvisionUserJob::new(&user))
        .await?;

    repo.save().await?;

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let cookie_jar = cookie_jar.set_session(&session);
    Ok((cookie_jar, url_builder.redirect(&next)).into_response())
}

async fn render(
    locale: DataLocale,
    ctx: RegisterContext,
    action: OptionalPostAuthAction,
    csrf_token: CsrfToken,
    repo: &mut impl RepositoryAccess,
    templates: &Templates,
    captcha_config: Option<CaptchaConfig>,
) -> Result<String, FancyError> {
    let next = action.load_context(repo).await?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx
        .with_captcha(captcha_config)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register(&ctx)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use hyper::{
        header::{CONTENT_TYPE, LOCATION},
        Request, StatusCode,
    };
    use mas_router::Route;
    use sqlx::PgPool;

    use crate::{
        test_utils::{
            setup, test_site_config, CookieHelper, RequestBuilderExt, ResponseExt, TestState,
        },
        SiteConfig,
    };

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_disabled(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_login_enabled: false,
                password_registration_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/login");

        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": "abc",
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Test the registration happy path
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the registration form
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Now if we get to the home page, we should see the user's username
        let request = Request::get("/").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("john"));
    }

    /// When the two password fields mismatch, it should give an error
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_password_mismatch(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the registration form
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "mismatch",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Password fields don't match"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_username_too_short(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the registration form
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "a",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("username too short"));
    }

    /// When the user already exists in the database, it should give an error
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_user_exists(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        // Insert a user in the database first
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Render the registration page and get the CSRF token
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the registration form
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("This username is already taken"));
    }

    /// When the username is already reserved on the homeserver, it should give
    /// an error
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_user_reserved(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Reserve "john" on the homeserver
        state.homeserver_connection.reserve_localpart("john").await;

        // Submit the registration form
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("This username is already taken"));
    }
}
