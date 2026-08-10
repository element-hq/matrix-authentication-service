// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::str::FromStr;

use axum::response::{Html, IntoResponse, Response};
use lettre::Address;
use mas_axum_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt as _, CsrfToken},
};
use mas_data_model::{BoxClock, BoxRng, CaptchaConfig, SiteConfig, UserRegistrationToken};
use mas_i18n::DataLocale;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{
    BoxRepository, RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SendEmailAuthenticationCodeJob},
    upstream_oauth2::UpstreamOAuthProviderRepository as _,
    user::{UserEmailRepository, UserRegistrationRepository as _, UserRepository},
};
use mas_templates::{
    FieldError, FormError, FormState, RegisterContext, RegisterFormField, TemplateContext,
    Templates, ToFormState as _,
};
use zeroize::Zeroizing;

use super::{RegisterForm, cookie::UserRegistrationSessions};
use crate::{
    BoundActivityTracker, Limiter, RequesterFingerprint, passwords::PasswordManager,
    views::shared::OptionalPostAuthAction,
};

/// Register a user with a password, from the form posted on `/register`. The
/// caller has verified the CSRF token, resolved the invite code the form
/// carried and checked that this registration is allowed.
#[tracing::instrument(name = "handlers.views.register.password", skip_all)]
#[expect(clippy::too_many_arguments)]
pub(super) async fn register(
    rng: &mut BoxRng,
    clock: &BoxClock,
    locale: DataLocale,
    password_manager: &PasswordManager,
    templates: &Templates,
    url_builder: &UrlBuilder,
    site_config: &SiteConfig,
    homeserver: &dyn HomeserverConnection,
    http_client: &reqwest::Client,
    limiter: &Limiter,
    requester: RequesterFingerprint,
    policy: &mut Policy,
    mut repo: BoxRepository,
    user_agent: Option<String>,
    activity_tracker: &BoundActivityTracker,
    query: OptionalPostAuthAction,
    cookie_jar: CookieJar,
    form: RegisterForm,
    registration_token: Option<UserRegistrationToken>,
    token_invalid: bool,
) -> Result<Response, InternalError> {
    let ip_address = activity_tracker.ip();

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, &mut *rng);

    // Validate the captcha
    // TODO: display a nice error message to the user
    let passed_captcha = form
        .captcha
        .verify(
            activity_tracker,
            http_client,
            url_builder.public_hostname(),
            site_config.captcha.as_ref(),
        )
        .await
        .is_ok();

    let state = form.to_form_state();

    let (pinned_username, pinned_email, passwordless) = match &registration_token {
        Some(token) => (
            token.username.as_deref(),
            token.email.as_deref(),
            token.passwordless,
        ),
        None => (None, None, false),
    };

    // An empty field means the user accepted whatever the invite code pins
    let username = match pinned_username {
        Some(pinned) if form.username.is_empty() => pinned.to_owned(),
        _ => form.username.clone(),
    };

    // The email field is only shown if the server requires it, but a
    // passwordless registration always needs one, as verifying it is what
    // establishes the user's identity. An invite code pinning an address also
    // forces it.
    let email = if site_config.password_registration_email_required
        || passwordless
        || pinned_email.is_some()
    {
        Some(match pinned_email {
            Some(pinned) if form.email.is_empty() => pinned.to_owned(),
            _ => form.email.clone(),
        })
    } else {
        None
    };

    // Validate the form
    let state = {
        let mut state = state;

        if !passed_captcha {
            state.add_error_on_form(FormError::Captcha);
        }

        if token_invalid {
            state.add_error_on_field(RegisterFormField::Token, FieldError::Invalid);
        }

        // An invite code may only be used to register the identity it was
        // issued for
        if pinned_username.is_some_and(|pinned| pinned != username) {
            state.add_error_on_field(RegisterFormField::Username, FieldError::Invalid);
        }

        if pinned_email.is_some_and(|pinned| Some(pinned) != email.as_deref()) {
            state.add_error_on_field(RegisterFormField::Email, FieldError::Invalid);
        }

        let mut homeserver_denied_username = false;
        if username.is_empty() {
            state.add_error_on_field(RegisterFormField::Username, FieldError::Required);
        } else if repo.user().exists(&username).await? {
            // The user already exists in the database
            state.add_error_on_field(RegisterFormField::Username, FieldError::Exists);
        } else if !homeserver
            .is_localpart_available(&username)
            .await
            .map_err(InternalError::from_anyhow)?
        {
            // The user already exists on the homeserver
            tracing::warn!(
                username = &username,
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

        // A passwordless invite code waives the password entirely. If we
        // couldn't resolve the code we don't know whether one is needed, so
        // don't pile up password errors on top of the code error either
        if !passwordless && !token_invalid {
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
        }

        // If the site has terms of service, the user must accept them
        if site_config.tos_uri.is_some() && form.accept_terms != "on" {
            state.add_error_on_field(RegisterFormField::AcceptTerms, FieldError::Required);
        }

        let res = policy
            .evaluate_register(mas_policy::RegisterInput {
                registration_method: mas_policy::RegistrationMethod::Password,
                username: &username,
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
                        code: violation.variant.map(|c| c.as_str()),
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
                            code: violation.variant.map(|c| c.as_str()),
                            message: violation.msg,
                        },
                    );
                }
                Some("password") => state.add_error_on_field(
                    RegisterFormField::Password,
                    FieldError::Policy {
                        code: violation.variant.map(|c| c.as_str()),
                        message: violation.msg,
                    },
                ),
                _ => state.add_error_on_form(FormError::Policy {
                    code: violation.variant.map(|c| c.as_str()),
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
            state,
            &query,
            csrf_token,
            &mut repo,
            templates,
            url_builder,
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
            &mut *rng,
            clock,
            username,
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

    let registration = if let Some(registration_token) = &registration_token {
        repo.user_registration()
            .set_registration_token(registration, registration_token)
            .await?
    } else {
        registration
    };

    let registration = if let Some(email) = email {
        // Create a new user email authentication session
        let user_email_authentication = repo
            .user_email()
            .add_authentication_for_registration(&mut *rng, clock, email, &registration)
            .await?;

        // Schedule a job to verify the email
        repo.queue_job()
            .schedule_job(
                &mut *rng,
                clock,
                SendEmailAuthenticationCodeJob::new(&user_email_authentication, locale.to_string()),
            )
            .await?;

        repo.user_registration()
            .set_email_authentication(registration, &user_email_authentication)
            .await?
    } else {
        registration
    };

    // A passwordless registration doesn't get a password at all: verifying the
    // email address is what establishes the user's identity
    let registration = if passwordless {
        registration
    } else {
        let password = Zeroizing::new(form.password);
        let (version, hashed_password) = password_manager
            .hash(&mut *rng, password)
            .await
            .map_err(InternalError::from_anyhow)?;

        repo.user_registration()
            .set_password(registration, hashed_password, version)
            .await?
    };

    repo.save().await?;

    let cookie_jar = UserRegistrationSessions::load(&cookie_jar)
        .add(&registration)
        .save(cookie_jar, clock);

    Ok((
        cookie_jar,
        url_builder.redirect(&mas_router::RegisterFinish::new(registration.id)),
    )
        .into_response())
}

/// Render the registration page again, with the errors the form collected
#[expect(clippy::too_many_arguments)]
async fn render(
    locale: DataLocale,
    form_state: FormState<RegisterFormField>,
    action: &OptionalPostAuthAction,
    csrf_token: CsrfToken,
    repo: &mut BoxRepository,
    templates: &Templates,
    url_builder: &UrlBuilder,
    captcha_config: Option<CaptchaConfig>,
) -> Result<String, InternalError> {
    let providers = repo.upstream_oauth_provider().all_enabled().await?;
    let ctx = RegisterContext::new(url_builder, providers, action.post_auth_action.as_ref())
        .with_form_state(form_state)
        .with_captcha(captcha_config)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register(&ctx)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use hyper::{
        Request, Response, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };
    use mas_router::Route;
    use mas_storage::{RepositoryAccess, user::UserRegistrationTokenRepository};
    use sqlx::PgPool;
    use ulid::Ulid;

    use super::super::tests::{csrf_token, mint_csrf_token};
    use crate::{
        SiteConfig,
        test_utils::{
            CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
        },
    };

    /// Extract and parse the form state the island was booted with
    fn form_state(body: &str) -> serde_json::Value {
        let raw = body
            .split("data-form='")
            .nth(1)
            .unwrap_or_else(|| panic!("no data-form attribute in body: {body}"))
            .split('\'')
            .next()
            .unwrap();
        serde_json::from_str(raw).unwrap()
    }

    /// Extract the registration ID out of the redirect the handler replies with
    fn registration_id(response: &Response<String>) -> Ulid {
        response
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .rsplit('/')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
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
        let csrf_token = csrf_token(response.body());

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
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        let csrf_token = csrf_token(response.body());

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
        assert_eq!(
            form_state(response.body())["fields"]["password_confirm"]["errors"],
            serde_json::json!([{"kind": "password_mismatch"}])
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_username_too_long(pool: PgPool) {
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
        let csrf_token = csrf_token(response.body());

        // Submit the registration form
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "a".repeat(256),
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
        assert_eq!(
            form_state(response.body())["fields"]["username"]["errors"][0]["code"],
            serde_json::json!("username-too-long")
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
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        let csrf_token = csrf_token(response.body());

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
        assert_eq!(
            form_state(response.body())["fields"]["username"]["errors"],
            serde_json::json!([{"kind": "exists"}])
        );
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
        let csrf_token = csrf_token(response.body());

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
        assert_eq!(
            form_state(response.body())["fields"]["username"]["errors"],
            serde_json::json!([{"kind": "exists"}])
        );
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
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        let csrf_token = csrf_token(response.body());

        // Submit the registration form without email
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "alice",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }),
        );
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
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        let csrf_token = csrf_token(response.body());

        // Submit the registration form with valid email
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "charlie",
                "email": "charlie@example.com",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }),
        );
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
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        let csrf_token = csrf_token(response.body());

        // Submit the registration form without email
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "david",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        assert_eq!(
            form_state(response.body())["fields"]["email"]["errors"],
            serde_json::json!([{"kind": "required"}])
        );

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
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        let csrf_token = csrf_token(response.body());

        // Submit the registration form with empty email
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "eve",
                "email": "",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        assert_eq!(
            form_state(response.body())["fields"]["email"]["errors"],
            serde_json::json!([{"kind": "required"}])
        );

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
        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        let csrf_token = csrf_token(response.body());

        // Submit the registration form with invalid email
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "grace",
                "email": "not-an-email",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        assert_eq!(
            form_state(response.body())["fields"]["email"]["errors"],
            serde_json::json!([{"kind": "invalid"}])
        );

        // Ensure no registration was created
        let mut repo = state.repository().await.unwrap();
        let user_exists = repo.user().exists("grace").await.unwrap();
        assert!(!user_exists);
    }

    /// A passwordless invite code lets the user register without a password,
    /// and pins the username and the email address it was issued for
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_with_passwordless_token(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let mut repo = state.repository().await.unwrap();
        repo.user_registration_token()
            .add(
                &mut rng,
                &state.clock,
                "invite_alice".to_owned(),
                None,
                None,
                Some("alice".to_owned()),
                Some("alice@example.com".to_owned()),
                true,
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        let csrf_token = csrf_token(response.body());

        // No password, no username and no email: they all come from the code
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "",
                "token": "invite_alice",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        let mut repo = state.repository().await.unwrap();
        let registration = repo
            .user_registration()
            .lookup(registration_id(&response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(registration.username, "alice");
        assert!(registration.password.is_none());
        assert!(registration.user_registration_token_id.is_some());

        // The email address from the code is the one being verified
        let email_authentication = repo
            .user_email()
            .lookup_authentication(registration.email_authentication_id.unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(email_authentication.email, "alice@example.com");
    }

    /// Registering with an invite code which is no longer valid is refused
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_with_revoked_token(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let mut repo = state.repository().await.unwrap();
        let token = repo
            .user_registration_token()
            .add(
                &mut rng,
                &state.clock,
                "revoked_invite".to_owned(),
                None,
                None,
                None,
                None,
                true,
            )
            .await
            .unwrap();
        repo.user_registration_token()
            .revoke(&state.clock, token)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        let csrf_token = csrf_token(response.body());

        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "bob",
                "email": "bob@example.com",
                "token": "revoked_invite",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert_eq!(
            form_state(response.body())["fields"]["token"]["errors"],
            serde_json::json!([{"kind": "invalid"}])
        );

        // No registration was created
        let mut repo = state.repository().await.unwrap();
        assert!(!repo.user().exists("bob").await.unwrap());
    }

    /// An invite code which pins a username can't be used to register another
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_with_token_username_mismatch(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let mut repo = state.repository().await.unwrap();
        repo.user_registration_token()
            .add(
                &mut rng,
                &state.clock,
                "invite_alice".to_owned(),
                None,
                None,
                Some("alice".to_owned()),
                None,
                false,
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        let csrf_token = csrf_token(response.body());

        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "mallory",
                "email": "mallory@example.com",
                "password": "correcthorsebatterystaple",
                "password_confirm": "correcthorsebatterystaple",
                "token": "invite_alice",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert_eq!(
            form_state(response.body())["fields"]["username"]["errors"],
            serde_json::json!([{"kind": "invalid"}])
        );

        // No registration was created
        let mut repo = state.repository().await.unwrap();
        assert!(!repo.user().exists("mallory").await.unwrap());
    }

    /// A passwordless invite code is a way to register on its own: it works
    /// with password registration off, and with passwords disabled entirely
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_with_passwordless_token_without_password_registration(pool: PgPool) {
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
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let mut repo = state.repository().await.unwrap();
        repo.user_registration_token()
            .add(
                &mut rng,
                &state.clock,
                "invite_alice".to_owned(),
                None,
                None,
                Some("alice".to_owned()),
                Some("alice@example.com".to_owned()),
                true,
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let csrf_token = mint_csrf_token(&state, &cookies);
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token.clone(),
                "token": "invite_alice",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        let mut repo = state.repository().await.unwrap();
        let registration = repo
            .user_registration()
            .lookup(registration_id(&response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(registration.username, "alice");
        assert!(registration.password.is_none());

        // The same request without the invite code has nothing to register with
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "mallory",
                "email": "mallory@example.com",
                "accept_terms": "on",
            }),
        );
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
    }
}
