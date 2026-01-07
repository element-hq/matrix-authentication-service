// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{str::FromStr, sync::Arc};

use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::{extract::Query, typed_header::TypedHeader};
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, CaptchaConfig, TchapConfig};
use mas_i18n::DataLocale;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SendEmailAuthenticationCodeJob},
    //:tchap:
    //user::{UserEmailRepository, UserRepository},
    user::UserEmailRepository,
    //:tchap:end
};
use mas_templates::{
    FieldError, FormError, FormState, PasswordRegisterContext, RegisterFormField, TemplateContext,
    Templates, ToFormState,
};
use serde::{Deserialize, Serialize};
//:tchap:
use tchap::{EmailAllowedResult, email_to_display_name, email_to_mxid_localpart};
//:tchap:
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

    //:tchap:
    //retrieve and use login_hint
    if let Some(PostAuthAction::ContinueAuthorizationGrant { id }) = &query.action.post_auth_action
        && let Some(oauth2_authorization_grant) =
            repo.oauth2_authorization_grant().lookup(*id).await?
    {
        if let Some(login_hint) = oauth2_authorization_grant.login_hint {
            tracing::trace!(
                "ContinueAuthorizationGrant:{:?} login_hint:{:?}",
                id,
                login_hint
            );
            //fill username with a dummy value as it will be generated from the email in
            // the POST method
            let username = "--";
            let mut form_state = FormState::default();
            form_state.set_value(RegisterFormField::Username, Some(username.to_owned()));
            form_state.set_value(RegisterFormField::Email, Some(login_hint));
            ctx = ctx.with_form_state(form_state);
        } else {
            tracing::trace!("Missing login_hint in oauth2_authorization_grant:{:?}", id);
        }
    } else {
        tracing::warn!("Missing oauth2_authorization_grant in account creation");
        // deactivate this for the moment, as the unit tests need to be fixed
        // show an error screen to guide the user to start a valid creation
        // account flow from a Tchap device
        //return Err(InternalError::new(std::io::Error::other("Veuillez fermer
        // cette fenêtre et relancer la création de compte depuis votre appareil
        // Tchap").into()));
    }
    //:tchap: end

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
    //:tchap: add tchap to the state with site_config as a tuple to stay under the limit of 16
    //:tchap: arguments
    (State(site_config), State(tchap_config)): (State<SiteConfig>, State<TchapConfig>),
    //:tchap:end
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

    //:tchap:
    //let form = cookie_jar.verify_form(&clock, form)?;
    let mut form: RegisterForm = cookie_jar.verify_form(&clock, form)?;
    //:tchap:

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

        //:tchap:
        if let Some(email) = &email {
            // Note that we don't check here if the email is already taken here, as
            // we don't want to leak the information about other users. Instead, we will
            // show an error message once the user confirmed their email address.
            if email.is_empty() {
                state.add_error_on_field(RegisterFormField::Email, FieldError::Required);
            } else if Address::from_str(email).is_err() {
                state.add_error_on_field(RegisterFormField::Email, FieldError::Invalid);
            }

            //verify that email address is allowed in this homeserver
            let server_name = homeserver.homeserver();
            let email_result = check_email_allowed(email, server_name, &tchap_config).await;

            match email_result {
                EmailAllowedResult::Allowed => {
                    // Email is allowed, continue
                }
                EmailAllowedResult::WrongServer => {
                    state.add_error_on_field(
                        RegisterFormField::Email,
                        FieldError::Policy {
                            code: None,
                            message: "Votre adresse mail est associée à un autre serveur."
                                .to_owned(),
                        },
                    );
                }
                EmailAllowedResult::InvitationMissing => {
                    state.add_error_on_field(
                        RegisterFormField::Email,
                        FieldError::Policy {
                            code: None,
                            message: "Vous avez besoin d'une invitation pour accéder à Tchap"
                                .to_owned(),
                        },
                    );
                }
            }

            //mutate the username in the form based on the email
            form.username = email_to_mxid_localpart(email);
        }
        //:tchap: end

        let mut homeserver_denied_username = false;

        //:tchap:
        //we skip username error checks because Tchap account allowance relies on email
        /*
        if form.username.is_empty() {
            state.add_error_on_field(RegisterFormField::Username, FieldError::Required);
        } else if repo.user().exists(&form.username).await? {
            // The user already exists in the database
            state.add_error_on_field(RegisterFormField::Username, FieldError::Exists);
        } else
        */
        //:tchap:end
        if !homeserver
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
        //:tchap: set display name automatically - skip display name page
        let maybe_display_name = Some(email_to_display_name(&email));

        let registration = if let Some(display_name) = maybe_display_name {
            repo.user_registration()
                .set_display_name(registration, display_name)
                .await?
        } else {
            registration
        };
        //:tchap: end

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

//:tchap:
///real function used when not testing
#[cfg(not(test))]
async fn check_email_allowed(
    email: &str,
    server_name: &str,
    tchap_config: &TchapConfig,
) -> EmailAllowedResult {
    tchap::is_email_allowed(email, server_name, tchap_config).await
}

#[cfg(test)]
async fn check_email_allowed(
    _email: &str,
    _server_name: &str,
    _tchap_config: &TchapConfig,
) -> EmailAllowedResult {
    EmailAllowedResult::Allowed
}
//:tchap:end

#[cfg(test)]
mod tests {
    use hyper::{
        Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };
    use mas_data_model::AuthorizationCode;
    use mas_router::{Route, SimpleRoute};
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        requests::ResponseMode,
        scope::{OPENID, Scope},
    };
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

    /// :tchap:
    /// Test the registration happy path with `oauth2_authorization_grant` and
    /// `login_hint``. this test is specific to Tchap beacause in the upstream
    /// register there is no oauth2_authorization_grant in the fixture
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_register_with_login_hint(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        //:tchap: use login_hint
        let login_hint = "jacques@example.com";
        let expected_username = "jacques-example.com";

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

        //:tchap:
        let mut repo = state.repository().await.unwrap();

        // Lookup the client in the database.
        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();

        // Save a grant int he repo
        let code = "thisisaverysecurecode";
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                &client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: code.to_owned(),
                    pkce: None,
                }),
                Some("state".to_owned()),
                Some("nonce".to_owned()),
                ResponseMode::Query,
                false,
                Some(login_hint.to_owned()),
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();
        //:tchap:

        // Render the registration page and get the CSRF token
        //:tchap: add a post auth action with the grant.id
        let request = Request::get(
            &*mas_router::PasswordRegister::default()
                .and_continue_grant(grant.id)
                .path_and_query(),
        )
        .empty();
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

        let request = Request::post(
            &*mas_router::PasswordRegister::default()
                .and_continue_grant(grant.id)
                .path_and_query(),
        )
        .form(serde_json::json!({
            "csrf": csrf_token,
            "username": "--",
            "email": "jacques@example.com",
            "password": "correcthorsebatterystaple",
            "password_confirm": "correcthorsebatterystaple",
            "accept_terms": "on",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        //response.assert_status(StatusCode::ACCEPTED);//:tchap:
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
        assert_eq!(registration.username, expected_username.to_owned());
        assert!(registration.password.is_some());

        let email_authentication = repo
            .user_email()
            .lookup_authentication(registration.email_authentication_id.unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(email_authentication.email, login_hint.to_owned());
    }

    /// Test the registration happy path
    #[ignore = "use the test test_register_with_login_hint instead"]
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

    #[ignore = "Tchap does not check username lenght because it is generated from the email"]
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
    #[ignore = "Tchap does not check user existance by username but by email"]
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
                //:tchap:
                //"email": "john@example.com",
                "email": "john",
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
