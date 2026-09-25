// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::{extract::Query, typed_header::TypedHeader};
use hyper::StatusCode;
use mas_axum_utils::{
    GenericError, InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt as _, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, SiteConfig, UpstreamOAuthProvider};
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::{Register, UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::{BoxRepository, upstream_oauth2::UpstreamOAuthProviderRepository};
use mas_templates::{RegisterContext, RegisterFormField, TemplateContext, Templates, ToFormState};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use super::shared::OptionalPostAuthAction;
use crate::{
    BoundActivityTracker, Limiter, MetadataCache, PreferredLanguage, RequesterFingerprint,
    captcha::Form as CaptchaForm, passwords::PasswordManager,
    upstream_oauth2::authorize::start_authorization,
};

mod cookie;
pub(crate) mod password;
pub(crate) mod steps;

pub use self::cookie::UserRegistrationSessions as UserRegistrationSessionsCookie;

/// The form was submitted with a provider which doesn't exist or isn't enabled
#[derive(Debug, Error)]
#[error("Upstream OAuth 2.0 provider not found")]
struct ProviderNotFound;

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
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
) -> Result<Response, InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    }

    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    // Without a password form there is nothing to show beyond the provider
    // buttons, which isn't worth a page for one provider or none
    if !site_config.password_registration_enabled {
        if providers.len() == 1 {
            let provider = providers.into_iter().next().unwrap();

            let mut destination = UpstreamOAuth2Authorize::new(provider.id);

            if let Some(action) = query.post_auth_action {
                destination = destination.and_then(action);
            }

            return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
        }

        if providers.is_empty() {
            let destination = mas_router::Login::from(query.post_auth_action);
            return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
        }
    }

    let mut ctx = RegisterContext::new(providers);
    let post_action = query
        .load_context(&mut repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    if let Some(action) = post_action {
        ctx = ctx.with_post_action(action);
    }

    let ctx = ctx
        .with_captcha(site_config.captcha.clone())
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_register(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

/// A localpart longer than this can never become an MXID (`@` + localpart +
/// `:` + server name is capped at 255 bytes), so there is no point carrying it
/// any further. The real limit is enforced by the register policy.
const MAX_USERNAME_LENGTH: usize = 255;

/// Every field defaults: the provider buttons submit this same form, and the
/// SSO-only page renders none of them.
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

// The tuples group extractors: axum implements `Handler` for at most 16 of them.
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
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<RegisterForm>>,
) -> Result<Response, InternalError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());

    let Ok(form) = cookie_jar.verify_form(&clock, form) else {
        // An invalid token most likely comes from a page left open past the CSRF token lifetime
        tracing::debug!("Invalid CSRF token on the registration form, redirecting to a fresh one");
        let destination = Register::from(query.post_auth_action);
        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    };

    // Carry the username along so we can prefill it if the user gets to pick
    // one when they come back
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

        // The username is carried in a cookie, so its size has to be bounded
        let username = form.username.trim();
        let username = if username.len() <= MAX_USERNAME_LENGTH {
            username
        } else {
            ""
        };
        let carried_username = (!username.is_empty()).then(|| username.to_owned());

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
            carried_username,
        )
        .await?;

        repo.save().await?;

        return Ok((cookie_jar, Redirect::to(url.as_str())).into_response());
    }

    if !site_config.password_registration_enabled {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    self::password::register(
        &mut rng,
        &clock,
        locale,
        &password_manager,
        &templates,
        &url_builder,
        &site_config,
        &*homeserver,
        &http_client,
        &limiter,
        requester,
        &mut policy,
        repo,
        user_agent,
        &activity_tracker,
        query,
        cookie_jar,
        form,
    )
    .await
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_axum_utils::csrf::CsrfExt as _;
    use mas_data_model::{
        CaptchaConfig, CaptchaService, Clock, UlidExt, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_storage::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthSessionRepository},
    };
    use oauth2_types::scope::{OPENID, Scope};
    use sqlx::PgPool;
    use ulid::Ulid;

    use super::MAX_USERNAME_LENGTH;
    use crate::{
        SiteConfig,
        test_utils::{
            CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
        },
    };

    /// Provision an upstream provider which needs no network access to start an
    /// authorization flow: discovery is disabled and the authorization endpoint
    /// is set explicitly
    async fn provider(state: &TestState) -> Ulid {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://upstream.example.com/".to_owned()),
                    human_name: Some("Upstream Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: Some(
                        "https://upstream.example.com/authorize".parse().unwrap(),
                    ),
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
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

    /// Render the registration page, saving its cookies and returning its CSRF
    /// token and body
    async fn render_page(state: &TestState, cookies: &CookieHelper) -> (String, String) {
        let request = cookies.with_cookies(Request::get("/register").empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);

        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .expect("the page should have a CSRF token")
            .split('\"')
            .next()
            .unwrap()
            .to_owned();

        (csrf_token, response.body().clone())
    }

    /// Mint a CSRF token out of band, for the configurations where the page
    /// doesn't render a form to read one from
    fn mint_csrf_token(state: &TestState, cookies: &CookieHelper) -> String {
        let (csrf_token, cookie_jar) = state.cookie_jar().csrf_token(&state.clock, state.rng());
        cookies.import(cookie_jar);
        csrf_token.form_value().clone()
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

    /// With no upstream provider, the page is the password registration form
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_without_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let (_csrf_token, body) = render_page(&state, &cookies).await;
        assert!(body.contains(r#"name="username""#));
        assert!(body.contains(r#"name="password""#));
        assert!(body.contains(r#"name="password_confirm""#));
    }

    /// The page renders with a CAPTCHA configured
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_with_captcha(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                captcha: Some(CaptchaConfig {
                    service: CaptchaService::HCaptcha,
                    site_key: "site-key".to_owned(),
                    secret_key: "secret-key".to_owned(),
                }),
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let cookies = CookieHelper::new();

        let (_csrf_token, body) = render_page(&state, &cookies).await;
        assert!(
            body.contains(r#"data-captcha-site-key="site-key""#),
            "response body: {body}"
        );
    }

    /// Without password registration, the page is just the provider buttons
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_password_disabled_with_providers(pool: PgPool) {
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

        let first = provider(&state).await;
        let second = provider(&state).await;

        let (_csrf_token, body) = render_page(&state, &cookies).await;
        assert!(body.contains(&format!(r#"name="provider" value="{first}""#)));
        assert!(body.contains(&format!(r#"name="provider" value="{second}""#)));
        assert!(!body.contains(r#"name="password""#));
    }

    /// With both password registration and a provider, the page carries the
    /// password form and the provider button, including when the form fails
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_password_enabled_with_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let provider_id = provider(&state).await;

        let (csrf_token, body) = render_page(&state, &cookies).await;
        assert!(body.contains(r#"name="password""#));
        assert!(body.contains(&format!(r#"name="provider" value="{provider_id}""#)));

        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "email": "john@example.com",
            "password": "hunter2",
            "password_confirm": "mismatch",
            "accept_terms": "on",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Password fields don't match"));
        assert!(
            response
                .body()
                .contains(&format!(r#"name="provider" value="{provider_id}""#))
        );
    }

    /// `/register/password` redirects to `/register`, keeping the query string
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_register_redirect(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let request = Request::get("/register/password?kind=change_password").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/register?kind=change_password");

        let request = Request::get("/register/password").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/register");
    }

    /// With password registration disabled and no upstream provider, there is
    /// nothing to register with
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

        let request = Request::get("/register").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/login");

        let csrf_token = mint_csrf_token(&state, &cookies);
        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "email": "john@example.com",
            "password": "hunter2",
            "password_confirm": "hunter2",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Submitting the form with a provider starts an upstream authorization
    /// flow, carrying the username and the post-auth action along in the cookie
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_with_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let provider_id = provider(&state).await;
        let (csrf_token, body) = render_page(&state, &cookies).await;

        // The provider is rendered as a submit button of the form
        assert!(body.contains(&format!(r#"name="provider" value="{provider_id}""#)));

        let grant = Ulid::from_datetime_with_rng(state.clock.now(), &mut state.rng());
        let request = cookies.with_cookies(
            Request::post(format!(
                "/register?kind=continue_authorization_grant&id={grant}"
            ))
            .form(serde_json::json!({
                "csrf": csrf_token,
                "username": "alice",
                "provider": provider_id.to_string(),
            })),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        assert!(
            location.starts_with("https://upstream.example.com/authorize?"),
            "unexpected location: {location}"
        );

        let sessions = upstream_sessions(&state, &response)
            .expect("the upstream sessions cookie should be set");
        assert_eq!(sessions[0]["username"], "alice");
        assert_eq!(
            sessions[0]["post_auth_action"],
            serde_json::json!({
                "kind": "continue_authorization_grant",
                "id": grant.to_string(),
            })
        );

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

    /// A form submitted with an invalid CSRF token starts nothing and sends the
    /// user back to a freshly rendered page
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_invalid_csrf(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let provider_id = provider(&state).await;
        let (csrf_token, _body) = render_page(&state, &cookies).await;

        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": format!("{csrf_token}invalid"),
            "username": "alice",
            "provider": provider_id.to_string(),
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/register");
        assert!(upstream_sessions(&state, &response).is_none());
    }

    /// A username too long to ever become an MXID is dropped instead of being
    /// carried in the cookie
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_with_overlong_username(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let provider_id = provider(&state).await;
        let (csrf_token, _body) = render_page(&state, &cookies).await;

        let username = "a".repeat(MAX_USERNAME_LENGTH + 1);
        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": csrf_token,
            "username": username,
            "provider": provider_id.to_string(),
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let sessions = upstream_sessions(&state, &response)
            .expect("the upstream sessions cookie should be set");
        assert!(sessions[0].get("username").is_none());

        // Password registration keeps the overlong username, and the policy rejects it
        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": csrf_token,
            "username": username,
            "email": "john@example.com",
            "password": "correcthorsebatterystaple",
            "password_confirm": "correcthorsebatterystaple",
            "accept_terms": "on",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        assert!(
            response.body().contains("Username is too long"),
            "response body: {}",
            response.body()
        );
    }

    /// Submitting a provider which doesn't exist gives a 404
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_with_unknown_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        provider(&state).await;
        let (csrf_token, _body) = render_page(&state, &cookies).await;

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
}
