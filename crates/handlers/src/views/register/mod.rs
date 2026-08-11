// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    Form,
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::Query;
use hyper::StatusCode;
use mas_axum_utils::{
    GenericError, InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt as _, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, SiteConfig, UpstreamOAuthProvider};
use mas_router::{PasswordRegister, UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::{BoxRepository, upstream_oauth2::UpstreamOAuthProviderRepository};
use mas_templates::{RegisterContext, TemplateContext, Templates};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use super::shared::OptionalPostAuthAction;
use crate::{
    BoundActivityTracker, MetadataCache, PreferredLanguage, impl_from_error_for_route,
    upstream_oauth2::{UpstreamSessionContext, authorize::start_authorization},
};

mod cookie;
pub(crate) mod password;
pub(crate) mod steps;

pub use self::cookie::UserRegistrationSessions as UserRegistrationSessionsCookie;

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error("Provider not found")]
    ProviderNotFound,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error>),
}

impl_from_error_for_route!(mas_axum_utils::csrf::CsrfError);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(crate::upstream_oauth2::authorize::StartAuthorizationError);

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        match self {
            e @ Self::ProviderNotFound => {
                GenericError::new(StatusCode::NOT_FOUND, e).into_response()
            }
            Self::Internal(e) => InternalError::new(e).into_response(),
        }
    }
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

    // If password-based login is disabled, and there is only one upstream provider,
    // we can directly start an authorization flow
    if !site_config.password_registration_enabled && providers.len() == 1 {
        let provider = providers.into_iter().next().unwrap();

        let mut destination = UpstreamOAuth2Authorize::new(provider.id);

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        }

        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    }

    // If password-based registration is enabled and there are no upstream
    // providers, we redirect to the password registration page
    if site_config.password_registration_enabled && providers.is_empty() {
        let mut destination = PasswordRegister::default();

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        }

        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    }

    let mut ctx = RegisterContext::new(providers);
    let post_action = query
        .load_context(&mut repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    if let Some(action) = post_action {
        ctx = ctx.with_post_action(action);
    }

    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_register(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RegisterForm {
    #[serde(default)]
    username: String,

    /// Which upstream provider the user chose, if any: each provider has its
    /// own submit button
    #[serde(default)]
    provider: Option<String>,

    #[serde(flatten)]
    action: OptionalPostAuthAction,
}

#[tracing::instrument(name = "handlers.views.register.post", skip_all)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(metadata_cache): State<MetadataCache>,
    State(url_builder): State<UrlBuilder>,
    State(http_client): State<reqwest::Client>,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<RegisterForm>>,
) -> Result<Response, RouteError> {
    let form = cookie_jar.verify_form(&clock, form)?;
    let username = form.username.trim();
    let post_auth_action = form.action.post_auth_action;

    // The user chose an upstream provider: start an authorization flow with it,
    // carrying the username they typed along so that we can prefill it if they
    // get to choose one when they come back
    if let Some(provider_id) = form.provider {
        let provider_id: Ulid = provider_id
            .parse()
            .map_err(|_| RouteError::ProviderNotFound)?;

        let provider = repo
            .upstream_oauth_provider()
            .lookup(provider_id)
            .await?
            .filter(UpstreamOAuthProvider::enabled)
            .ok_or(RouteError::ProviderNotFound)?;

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
            post_auth_action,
            context,
        )
        .await?;

        repo.save().await?;

        return Ok((cookie_jar, Redirect::to(url.as_str())).into_response());
    }

    // Else the user wants to register with a password: redirect to that page,
    // carrying the username in the query string so that the page can be
    // reloaded or bookmarked
    let mut destination = PasswordRegister::from(post_auth_action);
    if !username.is_empty() {
        destination = destination.with_username(username.to_owned());
    }

    Ok((cookie_jar, url_builder.redirect(&destination)).into_response())
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_data_model::{
        Clock, UlidExt, UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_storage::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthSessionRepository},
    };
    use oauth2_types::scope::{OPENID, Scope};
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

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

    /// Submitting the form with a provider starts an upstream authorization
    /// flow, carrying the username along in the cookie
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_with_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let provider_id = provider(&state).await;
        let (csrf_token, body) = render_page(&state, &cookies).await;

        // The provider is rendered as a submit button of the form
        assert!(body.contains(&format!(r#"name="provider" value="{provider_id}""#)));

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

    /// Submitting the form without a provider redirects to the password
    /// registration page, keeping the username and the post-auth action
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_without_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        provider(&state).await;
        let (csrf_token, _body) = render_page(&state, &cookies).await;

        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "alice",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/register/password?username=alice");

        // The post-auth action travels in the form, as hidden inputs
        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "alice",
            "kind": "change_password",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(
            LOCATION,
            "/register/password?username=alice&kind=change_password",
        );

        // An empty username is not carried over
        let request = cookies.with_cookies(Request::post("/register").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "  ",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/register/password");
    }

    /// A form submitted with an invalid CSRF token is rejected
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
        response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert!(upstream_sessions(&state, &response).is_none());
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
