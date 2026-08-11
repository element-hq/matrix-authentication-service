// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{str::FromStr, sync::Arc};

use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::{extract::Query, typed_header::TypedHeader};
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::{
    GenericError, InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt as _, CsrfToken, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, CaptchaConfig, SiteConfig, UpstreamOAuthProvider};
use mas_i18n::DataLocale;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::{UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::{
    BoxRepository, RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SendEmailAuthenticationCodeJob},
    upstream_oauth2::UpstreamOAuthProviderRepository as _,
    user::{UserEmailRepository, UserRepository},
};
use mas_templates::{
    FieldError, FormError, FormState, RegisterContext, RegisterFormField, TemplateContext,
    Templates, ToFormState,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

use super::shared::OptionalPostAuthAction;
use crate::{
    BoundActivityTracker, Limiter, MetadataCache, PreferredLanguage, RequesterFingerprint,
    captcha::Form as CaptchaForm,
    passwords::PasswordManager,
    upstream_oauth2::{UpstreamSessionContext, authorize::start_authorization},
};

mod cookie;
pub(crate) mod steps;

pub use self::cookie::UserRegistrationSessions as UserRegistrationSessionsCookie;

/// The form was submitted with a provider which doesn't exist or isn't enabled
#[derive(Debug, Error)]
#[error("Upstream OAuth 2.0 provider not found")]
struct ProviderNotFound;

/// Every field defaults: the upstream provider buttons submit this same form,
/// and the SSO-only variant of the page has no field but the username at all.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RegisterForm {
    #[serde(default)]
    username: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_confirm: String,
    #[serde(default)]
    accept_terms: String,

    /// Which upstream provider the user chose, if any: each provider has its
    /// own submit button
    #[serde(default, skip_serializing)]
    provider: Option<String>,

    #[serde(flatten, skip_serializing)]
    captcha: CaptchaForm,
}

impl ToFormState for RegisterForm {
    type Field = RegisterFormField;
}

#[derive(Deserialize)]
pub(crate) struct QueryParams {
    username: Option<String>,
    #[serde(flatten)]
    action: OptionalPostAuthAction,
}

#[tracing::instrument(name = "handlers.views.register.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<QueryParams>,
    cookie_jar: CookieJar,
) -> Result<Response, InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.action.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    }

    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    if !site_config.password_registration_enabled {
        // If password-based registration is disabled, and there is only one upstream
        // provider, we can directly start an authorization flow
        if providers.len() == 1 {
            let provider = providers.into_iter().next().unwrap();

            let mut destination = UpstreamOAuth2Authorize::new(provider.id);

            if let Some(action) = query.action.post_auth_action {
                destination = destination.and_then(action);
            }

            return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
        }

        // With no way to register at all, there is nothing to show on this page
        if providers.is_empty() {
            return Ok((
                cookie_jar,
                url_builder.redirect(&mas_router::Login::from(query.action.post_auth_action)),
            )
                .into_response());
        }
    }

    let mut ctx = RegisterContext::new(
        &url_builder,
        providers,
        query.action.post_auth_action.as_ref(),
    );

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

#[tracing::instrument(name = "handlers.views.register.post", skip_all)]
#[expect(clippy::too_many_arguments)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(password_manager): State<PasswordManager>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    (State(http_client), State(metadata_cache)): (State<reqwest::Client>, State<MetadataCache>),
    (State(limiter), requester): (State<Limiter>, RequesterFingerprint),
    mut policy: Policy,
    mut repo: BoxRepository,
    (user_agent, activity_tracker): (
        Option<TypedHeader<headers::UserAgent>>,
        BoundActivityTracker,
    ),
    Query(query): Query<QueryParams>,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<RegisterForm>>,
) -> Result<Response, InternalError> {
    let query = query.action;
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());

    let ip_address = activity_tracker.ip();

    let form = cookie_jar.verify_form(&clock, form)?;

    // The user chose an upstream provider: start an authorization flow with it,
    // carrying the username they typed along so that we can prefill it if they
    // get to choose one when they come back
    if let Some(provider_id) = &form.provider {
        let provider = match provider_id.parse::<Ulid>() {
            Ok(provider_id) => repo
                .upstream_oauth_provider()
                .lookup(provider_id)
                .await?
                .filter(UpstreamOAuthProvider::enabled),
            Err(_) => None,
        };

        let Some(provider) = provider else {
            return Ok(GenericError::new(StatusCode::NOT_FOUND, ProviderNotFound).into_response());
        };

        let username = form.username.trim();
        let context = (!username.is_empty()).then(|| UpstreamSessionContext {
            username: Some(username.to_owned()),
        });

        let (cookie_jar, url) = start_authorization(
            &mut rng,
            &clock,
            &metadata_cache,
            &http_client,
            &url_builder,
            &mut repo,
            cookie_jar,
            &provider,
            query.post_auth_action,
            context,
        )
        .await?;

        repo.save().await?;

        return Ok((cookie_jar, Redirect::to(url.as_str())).into_response());
    }

    if !site_config.password_registration_enabled {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

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
        let providers = repo.upstream_oauth_provider().all_enabled().await?;
        let ctx = RegisterContext::new(&url_builder, providers, query.post_auth_action.as_ref())
            .with_form_state(state);

        let content = render(
            locale,
            ctx,
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

    let cookie_jar = UserRegistrationSessionsCookie::load(&cookie_jar)
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
    ctx: RegisterContext,
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

    let content = templates.render_register(&ctx)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use hyper::{
        Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };
    use mas_axum_utils::csrf::CsrfExt as _;
    use mas_data_model::{
        Clock as _, UlidExt as _, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_router::Route;
    use mas_storage::{
        RepositoryAccess as _,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthSessionRepository as _},
    };
    use oauth2_types::scope::{OPENID, Scope};
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::{
        SiteConfig,
        test_utils::{
            CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
        },
    };

    /// Extract the CSRF token the form island was booted with
    fn csrf_token(body: &str) -> &str {
        body.split("data-csrf-token=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
    }

    /// Mint a CSRF token out of band, for the configurations where the page
    /// doesn't render a form to read one from
    fn mint_csrf_token(state: &TestState, cookies: &CookieHelper) -> String {
        let (csrf_token, cookie_jar) = state.cookie_jar().csrf_token(&state.clock, state.rng());
        cookies.import(cookie_jar);
        csrf_token.form_value().to_owned()
    }

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
        let cookies = CookieHelper::new();

        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/login");

        let csrf_token = mint_csrf_token(&state, &cookies);
        let request = Request::post(&*mas_router::Register::default().path_and_query()).form(
            serde_json::json!({
                "csrf": csrf_token,
                "username": "john",
                "email": "john@example.com",
                "password": "hunter2",
                "password_confirm": "hunter2",
            }),
        );
        let response = state.request(cookies.with_cookies(request)).await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Add an enabled upstream provider with the given human name. Discovery is
    /// disabled and the authorization endpoint set explicitly, so that starting
    /// a flow with it needs no network access.
    async fn add_provider(state: &TestState, human_name: &str) -> Ulid {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://upstream.example.com/".to_owned()),
                    human_name: Some(human_name.to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method:
                        UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: Some("secret".to_owned()),
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: Some(
                        "https://upstream.example.com/authorize".parse().unwrap(),
                    ),
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: UpstreamOAuthProviderDiscoveryMode::Disabled,
                    pkce_mode: UpstreamOAuthProviderPkceMode::Disabled,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        provider.id
    }

    /// Extract and parse a JSON data attribute the island was booted with
    fn json_attribute(body: &str, attribute: &str) -> serde_json::Value {
        let raw = body
            .split(&format!("{attribute}='"))
            .nth(1)
            .unwrap_or_else(|| panic!("no {attribute} attribute in body: {body}"))
            .split('\'')
            .next()
            .unwrap();
        serde_json::from_str(raw).unwrap()
    }

    /// The registration page hands the upstream providers to the island
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_shows_upstream_providers(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let provider_id = add_provider(&state, "Example").await;

        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(
            body.contains(r#"id="register-form""#),
            "response body: {body}"
        );
        assert_eq!(
            json_attribute(body, "data-providers"),
            serde_json::json!([{
                "name": "Example",
                "brand": null,
                "id": provider_id.to_string(),
            }])
        );
    }

    /// With password registration disabled, the island still mounts to render
    /// the upstream providers, as long as there is more than one
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_sso_only_registration(pool: PgPool) {
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
        add_provider(&state, "First").await;
        add_provider(&state, "Second").await;

        let request = Request::get(&*mas_router::Register::default().path_and_query()).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(
            body.contains(r#"id="register-form""#),
            "response body: {body}"
        );
        let providers = json_attribute(body, "data-providers");
        assert_eq!(providers.as_array().unwrap().len(), 2, "{providers:?}");
    }

    /// Decode the upstream sessions cookie set by the given response, if any
    fn upstream_sessions(
        state: &TestState,
        response: &hyper::Response<String>,
    ) -> Option<serde_json::Value> {
        let cookies = CookieHelper::new();
        cookies.save_cookies(response);
        let request = cookies.with_cookies(Request::get("/").empty());
        state
            .cookie_manager
            .cookie_jar_from_headers(request.headers())
            .load("upstream-oauth2-sessions")
            .expect("the upstream sessions cookie should decode")
    }

    /// Render the registration page, saving its cookies and returning its CSRF
    /// token and body
    async fn render_page(
        state: &TestState,
        cookies: &CookieHelper,
        path: &str,
    ) -> (String, String) {
        let request = cookies.with_cookies(Request::get(path).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);

        (
            csrf_token(response.body()).to_owned(),
            response.body().clone(),
        )
    }

    /// Submitting the form with a provider starts an upstream authorization
    /// flow, carrying the username along in the cookie
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_with_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let provider_id = add_provider(&state, "Example").await;
        let (csrf_token, _body) = render_page(&state, &cookies, "/register").await;

        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "alice",
            "provider": provider_id.to_string(),
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        assert!(
            location.starts_with("https://upstream.example.com/authorize?"),
            "unexpected location: {location}"
        );

        // The upstream sessions cookie carries both the session and the username
        let sessions = upstream_sessions(&state, &response)
            .expect("the upstream sessions cookie should be set");
        assert_eq!(sessions[0]["context"]["username"], "alice");

        // And we recorded the session it points to
        let session_id: Ulid = sessions[0]["session"].as_str().unwrap().parse().unwrap();
        let mut repo = state.repository().await.unwrap();
        let session = repo
            .upstream_oauth_session()
            .lookup(session_id)
            .await
            .unwrap()
            .expect("the upstream authorization session should exist");
        assert_eq!(session.provider_id, provider_id);
    }

    /// The post-auth action travels in the query string, since the island form
    /// posts to the page's own URL
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_with_provider_keeps_post_auth_action(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let provider_id = add_provider(&state, "Example").await;
        let path = mas_router::Register::from(Some(mas_router::PostAuthAction::ChangePassword))
            .path_and_query();
        let (csrf_token, _body) = render_page(&state, &cookies, &path).await;

        let request = cookies.with_cookies(Request::post(&*path).form(serde_json::json!({
            "csrf": csrf_token,
            "username": "alice",
            "provider": provider_id.to_string(),
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let sessions = upstream_sessions(&state, &response)
            .expect("the upstream sessions cookie should be set");
        assert_eq!(
            sessions[0]["post_auth_action"],
            serde_json::json!({ "kind": "change_password" })
        );
    }

    /// The provider buttons work when password registration is disabled, where
    /// they are the only thing on the page
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_with_provider_sso_only(pool: PgPool) {
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
        let cookies = CookieHelper::new();

        let provider_id = add_provider(&state, "First").await;
        add_provider(&state, "Second").await;
        let (csrf_token, _body) = render_page(&state, &cookies, "/register").await;

        // No username field on that page, so the form is just the CSRF token
        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": csrf_token,
            "provider": provider_id.to_string(),
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let sessions = upstream_sessions(&state, &response)
            .expect("the upstream sessions cookie should be set");
        assert_eq!(sessions[0]["context"], serde_json::Value::Null);
    }

    /// A form submitted with an invalid CSRF token is rejected
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_invalid_csrf(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let provider_id = add_provider(&state, "Example").await;
        let (csrf_token, _body) = render_page(&state, &cookies, "/register").await;

        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": format!("{csrf_token}invalid"),
            "username": "alice",
            "provider": provider_id.to_string(),
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert!(upstream_sessions(&state, &response).is_none());
    }

    /// Submitting a provider which doesn't exist gives a 404
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_with_unknown_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        add_provider(&state, "Example").await;
        let (csrf_token, _body) = render_page(&state, &cookies, "/register").await;

        let unknown = Ulid::from_datetime_with_rng(state.clock.now(), &mut state.rng());
        for provider in [unknown.to_string(), "not-a-ulid".to_owned()] {
            let request =
                cookies.with_cookies(Request::post("/register").form(serde_json::json!({
                    "csrf": csrf_token,
                    "username": "alice",
                    "provider": provider,
                })));
            let response = state.request(request).await;
            response.assert_status(StatusCode::NOT_FOUND);
        }
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
        // The form state is handed to the client-side form as JSON
        assert!(
            response.body().contains("password_mismatch"),
            "response body: {}",
            response.body()
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
        assert!(
            response.body().contains("\"code\":\"username-too-long\""),
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
        assert!(
            response
                .body()
                .contains("\"username\":{\"errors\":[{\"kind\":\"exists\"}]"),
            "response body: {}",
            response.body()
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
        assert!(
            response
                .body()
                .contains("\"username\":{\"errors\":[{\"kind\":\"exists\"}]"),
            "response body: {}",
            response.body()
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

        // Check that the response contains an error on the email field
        assert!(
            response
                .body()
                .contains("\"email\":{\"errors\":[{\"kind\":\"required\"}]"),
            "response body: {}",
            response.body()
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

        // Check that the response contains an error on the email field
        assert!(
            response
                .body()
                .contains("\"email\":{\"errors\":[{\"kind\":\"required\"}]"),
            "response body: {}",
            response.body()
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

        // Check that the response contains an error on the email field
        assert!(
            response
                .body()
                .contains("\"email\":{\"errors\":[{\"kind\":\"invalid\"}]"),
            "response body: {}",
            response.body()
        );

        // Ensure no registration was created
        let mut repo = state.repository().await.unwrap();
        let user_exists = repo.user().exists("grace").await.unwrap();
        assert!(!user_exists);
    }
}
