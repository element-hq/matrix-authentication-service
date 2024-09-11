// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::typed_header::TypedHeader;
use hyper::StatusCode;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, CsrfToken, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_data_model::{BrowserSession, UserAgent};
use mas_i18n::DataLocale;
use mas_matrix::{BoxHomeserverConnection, HomeserverConnection, ProvisionRequest};
use mas_router::{UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::{
    upstream_oauth2::UpstreamOAuthProviderRepository,
    user::{BrowserSessionRepository, UserPasswordRepository, UserRepository},
    BoxClock, BoxRepository, BoxRng, Clock, Repository, RepositoryAccess, RepositoryError,
};
use mas_templates::{
    FieldError, FormError, LoginContext, LoginFormField, TemplateContext, Templates, ToFormState,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use super::shared::OptionalPostAuthAction;
use crate::{
    compat::login::{
        authenticate_via_rest_api, start_new_session, user_password_login, RouteError,
    },
    passwords::PasswordManager,
    BoundActivityTracker, Limiter, PreferredLanguage, RequesterFingerprint, SiteConfig,
};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
}

impl ToFormState for LoginForm {
    type Field = LoginFormField;
}

#[tracing::instrument(name = "handlers.views.login.get", skip_all, err)]
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
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    };

    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    // If password-based login is disabled, and there is only one upstream provider,
    // we can directly start an authorization flow
    if !site_config.password_login_enabled && providers.len() == 1 {
        let provider = providers.into_iter().next().unwrap();

        let mut destination = UpstreamOAuth2Authorize::new(provider.id);

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        };

        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    };

    let content = render(
        locale,
        LoginContext::default().with_upstream_providers(providers),
        query,
        csrf_token,
        &mut repo,
        &templates,
    )
    .await?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(name = "handlers.views.login.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(password_manager): State<PasswordManager>,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(limiter): State<Limiter>,
    State(homeserver): State<BoxHomeserverConnection>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    requester: RequesterFingerprint,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    Form(form): Form<ProtectedForm<LoginForm>>,
) -> Result<Response, FancyError> {
    let user_agent = user_agent.map(|ua| UserAgent::parse(ua.as_str().to_owned()));
    if !site_config.password_login_enabled {
        // XXX: is it necessary to have better errors here?
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    // Validate the form
    let state = {
        let mut state = form.to_form_state();

        if form.username.is_empty() {
            state.add_error_on_field(LoginFormField::Username, FieldError::Required);
        }

        if form.password.is_empty() {
            state.add_error_on_field(LoginFormField::Password, FieldError::Required);
        }

        state
    };

    if !state.is_valid() {
        let providers = repo.upstream_oauth_provider().all_enabled().await?;
        let content = render(
            locale,
            LoginContext::default()
                .with_form_state(state)
                .with_upstream_providers(providers),
            query,
            csrf_token,
            &mut repo,
            &templates,
        )
        .await?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    match login(
        password_manager,
        &mut repo,
        rng,
        &clock,
        limiter,
        requester,
        &form.username,
        &form.password,
        user_agent,
        homeserver,
    )
    .await
    {
        Ok(session_info) => {
            repo.save().await?;

            activity_tracker
                .record_browser_session(&clock, &session_info)
                .await;

            let cookie_jar = cookie_jar.set_session(&session_info);
            let reply = query.go_next(&url_builder);
            Ok((cookie_jar, reply).into_response())
        }
        Err(e) => {
            let state = state.with_error_on_form(e);

            let content = render(
                locale,
                LoginContext::default().with_form_state(state),
                query,
                csrf_token,
                &mut repo,
                &templates,
            )
            .await?;

            Ok((cookie_jar, Html(content)).into_response())
        }
    }
}

// TODO: move that logic elsewhere?
async fn login(
    password_manager: PasswordManager,
    repo: &mut Box<dyn Repository<RepositoryError> + Send + Sync>,
    mut rng: impl Rng + CryptoRng + Send,
    clock: &impl Clock,
    limiter: Limiter,
    requester: RequesterFingerprint,
    username: &str,
    password: &str,
    user_agent: Option<UserAgent>,
    homeserver: Box<dyn HomeserverConnection<Error = anyhow::Error>>,
) -> Result<BrowserSession, FormError> {
    // XXX: we're loosing the error context here
    let mxid: String = homeserver.mxid(&username);
    let user = if let Ok(Some(rest_auth_provider)) = password_manager.get_rest_auth_provider() {
        // If rest_auth_provider is enabled, authenticate via REST API
        let authenticated =
            authenticate_via_rest_api(mxid.clone(), password.to_owned(), rest_auth_provider)
                .await
                .map_err(|_err| FormError::InvalidCredentials)?;
        if authenticated {
            let user = repo
                .user()
                .find_by_username(&username)
                .await
                .map_err(|_err| FormError::Internal)?
                .filter(mas_data_model::User::is_valid);

            let user = match user {
                Some(user) => {
                    // User found: proceed
                    user
                }
                None => {
                    // User not found while existing in the provider: create it
                    let homeserver_available = homeserver
                        .is_localpart_available(&mxid)
                        .await
                        .map_err(|_err| FormError::Internal)?;
                    if !homeserver_available {
                        return Err(FormError::Internal);
                    }

                    let new_user = repo
                        .user()
                        .add(&mut rng, clock, mxid.clone())
                        .await
                        .map_err(|_err| FormError::Internal)?;

                    // Replicate in Synapse
                    homeserver
                        .provision_user(&ProvisionRequest::new(mxid.clone(), username.to_string()))
                        .await
                        .unwrap();

                    new_user
                }
            };
            // Update the password if needed
            let result = password_manager
                .hash(&mut rng, password.to_string().into_bytes().into())
                .await;
            let (version, hashed_password) = match result {
                Ok((version, hashed_password)) => (version, hashed_password),
                Err(_err) => return Err(FormError::Internal),
            };
            repo.user_password()
                .upsert(&mut rng, clock, &user, version, hashed_password)
                .await
                .map_err(|_err| FormError::Internal)?;

            user
        } else {
            return Err(FormError::InvalidCredentials);
        }
    } else {
        // If rest_auth_provider is not enabled, proceed with the normal authentication
        let user = user_password_login(
            &mut rng,
            clock,
            &password_manager,
            &limiter,
            requester,
            repo,
            username.to_string(),
            password.to_string(),
        )
        .await
        .map_err(|err| match err {
            RouteError::RateLimited(_) => FormError::RateLimitExceeded,
            RouteError::PasswordVerificationFailed(_)
            | RouteError::UserNotFound
            | RouteError::NoPassword => FormError::InvalidCredentials,
            _ => FormError::Internal,
        })?;
        user
    };

    // Start a new compat session without verifying the password again
    start_new_session(&mut rng, clock, repo, user.clone(), None)
        .await
        .map_err(|_err| FormError::Internal)?;
    // Start a new session
    let user_session = repo
        .browser_session()
        .add(&mut rng, clock, &user, user_agent)
        .await
        .map_err(|_| FormError::Internal)?;

    let user_password = repo
        .user_password()
        .active(&user)
        .await
        .map_err(|_| FormError::InvalidCredentials)?
        .ok_or(FormError::InvalidCredentials)?;

    // And mark it as authenticated by the password
    repo.browser_session()
        .authenticate_with_password(&mut rng, clock, &user_session, &user_password)
        .await
        .map_err(|_| FormError::Internal)?;

    Ok(user_session)
}

async fn render(
    locale: DataLocale,
    ctx: LoginContext,
    action: OptionalPostAuthAction,
    csrf_token: CsrfToken,
    repo: &mut impl RepositoryAccess,
    templates: &Templates,
) -> Result<String, FancyError> {
    let next = action.load_context(repo).await?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_login(&ctx)?;
    Ok(content)
}

#[cfg(test)]
mod test {
    use hyper::{
        header::{CONTENT_TYPE, LOCATION},
        Request, StatusCode,
    };
    use mas_data_model::UpstreamOAuthProviderClaimsImports;
    use mas_iana::oauth::OAuthClientAuthenticationMethod;
    use mas_router::Route;
    use mas_storage::{
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
        RepositoryAccess,
    };
    use mas_templates::escape_html;
    use oauth2_types::scope::OPENID;
    use sqlx::PgPool;
    use zeroize::Zeroizing;

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
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let mut rng = state.rng();

        // Without password login and no upstream providers, we should get an error
        // message
        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(
            response.body().contains("No login methods available"),
            "Response body: {}",
            response.body()
        );

        // Adding an upstream provider should redirect to it
        let mut repo = state.repository().await.unwrap();
        let first_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: "https://first.com/".to_owned(),
                    human_name: Some("First Ltd.".to_owned()),
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: OAuthClientAuthenticationMethod::None,
                    token_endpoint_signing_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    additional_authorization_parameters: Vec::new(),
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let first_provider_login = mas_router::UpstreamOAuth2Authorize::new(first_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, &first_provider_login.path_and_query());

        // Adding a second provider should show a login page with both providers
        let mut repo = state.repository().await.unwrap();
        let second_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: "https://second.com/".to_owned(),
                    human_name: None,
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: OAuthClientAuthenticationMethod::None,
                    token_endpoint_signing_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    additional_authorization_parameters: Vec::new(),
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let second_provider_login = mas_router::UpstreamOAuth2Authorize::new(second_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains(&escape_html("First Ltd.")));
        assert!(response
            .body()
            .contains(&escape_html(&first_provider_login.path_and_query())));
        assert!(response.body().contains(&escape_html("second.com")));
        assert!(response
            .body()
            .contains(&escape_html(&second_provider_login.path_and_query())));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        let (version, hash) = state
            .password_manager
            .hash(&mut rng, Zeroizing::new("hunter2".as_bytes().to_vec()))
            .await
            .unwrap();
        repo.user_password()
            .add(&mut rng, &state.clock, &user, version, hash, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
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

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
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

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_rate_limit(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        // Provision a user without a password.
        // We don't give that user a password, so that we skip hashing it in this test.
        // It will still be rate-limited
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
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

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);

        // First three attempts should just tell about the invalid credentials
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        // The fourth attempt should be rate-limited
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(!body.contains("Invalid credentials"));
        assert!(body.contains("too many requests"));
    }
}
