// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{str::FromStr, sync::Arc};

use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::typed_header::TypedHeader;
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, CaptchaConfig};
use mas_i18n::DataLocale;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{
    BoxRepository, RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SendEmailAuthenticationCodeJob},
    user::{UserEmailRepository, UserRepository},
};
use mas_templates::{
    FieldError, FormError, FormState, PasswordRegisterContext, RegisterFormField, TemplateContext,
    Templates, ToFormState,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::cookie::UserRegistrationSessions;
use crate::{
    BoundActivityTracker, Limiter, PreferredLanguage, RequesterFingerprint, SiteConfig,
    captcha::Form as CaptchaForm, passwords::PasswordManager,
    views::shared::OptionalPostAuthAction,
};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RegisterForm {
    username: String,
    #[serde(default)]
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

#[derive(Deserialize)]
pub struct QueryParams {
    username: Option<String>,
    #[serde(flatten)]
    action: OptionalPostAuthAction,
}

#[tracing::instrument(name = "handlers.views.password_register.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    mut repo: BoxRepository,
    Query(query): Query<QueryParams>,
    cookie_jar: CookieJar,
) -> Result<Response, InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if maybe_session.is_some() {
        let reply = query.action.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    }

    if !site_config.password_registration_enabled {
        // If password-based registration is disabled, redirect to the login page here
        return Ok(url_builder
            .redirect(&mas_router::Login::from(query.action.post_auth_action))
            .into_response());
    }

    let mut ctx = PasswordRegisterContext::default();

    // If we got a username from the query string, use it to prefill the form
    if let Some(username) = query.username {
        let mut form_state = FormState::default();
        form_state.set_value(RegisterFormField::Username, Some(username));
        ctx = ctx.with_form_state(form_state);
    }

    let content = render(
        locale,
        ctx,
        query.action,
        csrf_token,
        &mut repo,
        &templates,
        site_config.captcha.clone(),
    )
    .await?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(name = "handlers.views.password_register.post", skip_all)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(password_manager): State<PasswordManager>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
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
) -> Result<Response, InternalError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());

    let ip_address = activity_tracker.ip();
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

    let state = form.to_form_state();

    // The email form is only shown if the server requires it
    let email = site_config
        .password_registration_email_required
        .then_some(form.email);

    // Validate the form
    let state = {
        let mut state = state;

        if !passed_captcha {
            state.add_error_on_form(FormError::Captcha);
        }

        let mut homeserver_denied_username = false;
        if form.username.is_empty() {
            state.add_error_on_field(RegisterFormField::Username, FieldError::Required);
        } else if repo.user().exists(&form.username).await? {
            // The user already exists in the database
            state.add_error_on_field(RegisterFormField::Username, FieldError::Exists);
        } else if !homeserver
            .is_localpart_available(&form.username)
            .await
            .map_err(InternalError::from_anyhow)?
        {
            // The user already exists on the homeserver
            tracing::warn!(
                username = &form.username,
                "Homeserver denied username provided by user"
            );

            // We defer adding the error on the field, until we know whether we had another
            // error from the policy, to avoid showing both
            homeserver_denied_username = true;
        }

        if let Some(email) = &email {
            // Note that we don't check here if the email is already taken here, as
            // we don't want to leak the information about other users. Instead, we will
            // show an error message once the user confirmed their email address.
            if email.is_empty() {
                state.add_error_on_field(RegisterFormField::Email, FieldError::Required);
            } else if Address::from_str(email).is_err() {
                state.add_error_on_field(RegisterFormField::Email, FieldError::Invalid);
            }
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
                    code: None,
                    message: "Password is too weak".to_owned(),
                },
            );
        }

        // If the site has terms of service, the user must accept them
        if site_config.tos_uri.is_some() && form.accept_terms != "on" {
            state.add_error_on_field(RegisterFormField::AcceptTerms, FieldError::Required);
        }

        let res = policy
            .evaluate_register(mas_policy::RegisterInput {
                registration_method: mas_policy::RegistrationMethod::Password,
                username: &form.username,
                email: email.as_deref(),
                requester: mas_policy::Requester {
                    ip_address: activity_tracker.ip(),
                    user_agent: user_agent.clone(),
                },
            })
            .await?;

        for violation in res.violations {
            match violation.field.as_deref() {
                Some("email") => state.add_error_on_field(
                    RegisterFormField::Email,
                    FieldError::Policy {
                        code: violation.code.map(|c| c.as_str()),
                        message: violation.msg,
                    },
                ),
                Some("username") => {
                    // If the homeserver denied the username, but we also had an error on the policy
                    // side, we don't want to show both, so we reset the state here
                    homeserver_denied_username = false;
                    state.add_error_on_field(
                        RegisterFormField::Username,
                        FieldError::Policy {
                            code: violation.code.map(|c| c.as_str()),
                            message: violation.msg,
                        },
                    );
                }
                Some("password") => state.add_error_on_field(
                    RegisterFormField::Password,
                    FieldError::Policy {
                        code: violation.code.map(|c| c.as_str()),
                        message: violation.msg,
                    },
                ),
                _ => state.add_error_on_form(FormError::Policy {
                    code: violation.code.map(|c| c.as_str()),
                    message: violation.msg,
                }),
            }
        }

        if homeserver_denied_username {
            // XXX: we may want to return different errors like "this username is reserved"
            state.add_error_on_field(RegisterFormField::Username, FieldError::Exists);
        }

        if state.is_valid() {
            // Check the rate limit if we are about to process the form
            if let Err(e) = limiter.check_registration(requester) {
                tracing::warn!(error = &e as &dyn std::error::Error);
                state.add_error_on_form(FormError::RateLimitExceeded);
            }

            if let Some(email) = &email
                && let Err(e) = limiter.check_email_authentication_email(requester, email)
            {
                tracing::warn!(error = &e as &dyn std::error::Error);
                state.add_error_on_form(FormError::RateLimitExceeded);
            }
        }

        state
    };

    if !state.is_valid() {
        let content = render(
            locale,
            PasswordRegisterContext::default().with_form_state(state),
            query,
            csrf_token,
            &mut repo,
            &templates,
            site_config.captcha.clone(),
        )
        .await?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    let post_auth_action = query
        .post_auth_action
        .map(serde_json::to_value)
        .transpose()?;
    let registration = repo
        .user_registration()
        .add(
            &mut rng,
            &clock,
            form.username,
            ip_address,
            user_agent,
            post_auth_action,
        )
        .await?;

    let registration = if let Some(tos_uri) = &site_config.tos_uri {
        repo.user_registration()
            .set_terms_url(registration, tos_uri.clone())
            .await?
    } else {
        registration
    };

    let registration = if let Some(email) = email {
        // Create a new user email authentication session
        let user_email_authentication = repo
            .user_email()
            .add_authentication_for_registration(&mut rng, &clock, email, &registration)
            .await?;

        // Schedule a job to verify the email
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SendEmailAuthenticationCodeJob::new(&user_email_authentication, locale.to_string()),
            )
            .await?;

        repo.user_registration()
            .set_email_authentication(registration, &user_email_authentication)
            .await?
    } else {
        registration
    };

    // Hash the password
    let password = Zeroizing::new(form.password);
    let (version, hashed_password) = password_manager
        .hash(&mut rng, password)
        .await
        .map_err(InternalError::from_anyhow)?;

    // Add the password to the registration
    let registration = repo
        .user_registration()
        .set_password(registration, hashed_password, version)
        .await?;

    repo.save().await?;

    let cookie_jar = UserRegistrationSessions::load(&cookie_jar)
        .add(&registration)
        .save(cookie_jar, &clock);

    Ok((
        cookie_jar,
        url_builder.redirect(&mas_router::RegisterFinish::new(registration.id)),
    )
        .into_response())
}

async fn render(
    locale: DataLocale,
    ctx: PasswordRegisterContext,
    action: OptionalPostAuthAction,
    csrf_token: CsrfToken,
    repo: &mut impl RepositoryAccess,
    templates: &Templates,
    captcha_config: Option<CaptchaConfig>,
) -> Result<String, InternalError> {
    let next = action
        .load_context(repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx
        .with_captcha(captcha_config)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_password_register(&ctx)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use hyper::{
        Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };
    use mas_router::Route;
    use sqlx::PgPool;

    use crate::{
        SiteConfig,
        test_utils::{
            CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
        },
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

        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/login");

        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": "abc",
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
            }));
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
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(LOCATION).unwrap();

        // The handler redirects with the ID as the second to last portion of the path
        let id = location
            .to_str()
            .unwrap()
            .rsplit('/')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        // There should be a new registration in the database
        let mut repo = state.repository().await.unwrap();
        let registration = repo.user_registration().lookup(id).await.unwrap().unwrap();
        assert_eq!(registration.username, "john".to_owned());
        assert!(registration.password.is_some());

        let email_authentication = repo
            .user_email()
            .lookup_authentication(registration.email_authentication_id.unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(email_authentication.email, "john@example.com");
    }

    /// When the two password fields mismatch, it should give an error
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_password_mismatch(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "mismatch",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Password fields don't match"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_username_too_long(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "a".repeat(256),
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(
            response.body().contains("Username is too long"),
            "response body: {}",
            response.body()
        );
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
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
                "accept_terms": "on",
            }));
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
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("This username is already taken"));
    }

    /// Test registration without email when email is not required
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_without_email_when_not_required(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_registration_email_required: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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

        // Submit the registration form without email
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "alice",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(LOCATION).unwrap();

        // The handler redirects with the ID as the second to last portion of the path
        let id = location
            .to_str()
            .unwrap()
            .rsplit('/')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        // There should be a new registration in the database
        let mut repo = state.repository().await.unwrap();
        let registration = repo.user_registration().lookup(id).await.unwrap().unwrap();
        assert_eq!(registration.username, "alice".to_owned());
        assert!(registration.password.is_some());
        // Email authentication should be None when email is not required and not
        // provided
        assert!(registration.email_authentication_id.is_none());
    }

    /// Test registration with valid email when email is not required
    /// (email input is ignored completely when not required)
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_with_email_when_not_required(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_registration_email_required: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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

        // Submit the registration form with valid email
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "charlie",
                "email": "charlie@example.com",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(LOCATION).unwrap();

        // The handler redirects with the ID as the second to last portion of the path
        let id = location
            .to_str()
            .unwrap()
            .rsplit('/')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        // There should be a new registration in the database
        let mut repo = state.repository().await.unwrap();
        let registration = repo.user_registration().lookup(id).await.unwrap().unwrap();
        assert_eq!(registration.username, "charlie".to_owned());
        assert!(registration.password.is_some());

        // Email authentication should be None when email is not required
        // (email input is completely ignored in this case)
        assert!(registration.email_authentication_id.is_none());
    }

    /// Test registration fails when email is required but not provided
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_fails_without_email_when_required(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_registration_email_required: true,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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

        // Submit the registration form without email
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "david",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Check that the response contains an error about the email field
        let body = response.body();
        assert!(body.contains("email") || body.contains("Email"));

        // Ensure no registration was created
        let mut repo = state.repository().await.unwrap();
        let user_exists = repo.user().exists("david").await.unwrap();
        assert!(!user_exists);
    }

    /// Test registration fails when email is required but empty
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_fails_with_empty_email_when_required(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_registration_email_required: true,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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

        // Submit the registration form with empty email
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "eve",
                "email": "",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Check that the response contains an error about the email field
        let body = response.body();
        assert!(body.contains("email") || body.contains("Email"));

        // Ensure no registration was created
        let mut repo = state.repository().await.unwrap();
        let user_exists = repo.user().exists("eve").await.unwrap();
        assert!(!user_exists);
    }

    /// Test registration fails with invalid email when email is required
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_fails_with_invalid_email_when_required(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_registration_email_required: true,
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        // Render the registration page and get the CSRF token
        let request =
            Request::get(&*mas_router::PasswordRegister::default().path_and_query()).empty();
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

        // Submit the registration form with invalid email
        let request = Request::post(&*mas_router::PasswordRegister::default().path_and_query())
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "grace",
                "email": "not-an-email",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        // Check that the response contains an error about the email field
        let body = response.body();
        assert!(body.contains("email") || body.contains("Email"));

        // Ensure no registration was created
        let mut repo = state.repository().await.unwrap();
        let user_exists = repo.user().exists("grace").await.unwrap();
        assert!(!user_exists);
    }
}
