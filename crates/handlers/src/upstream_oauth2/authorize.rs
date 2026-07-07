// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::BTreeMap;

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::Query;
use chrono::Duration;
use hyper::StatusCode;
use mas_axum_utils::{GenericError, InternalError, SessionInfoExt, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng, UpstreamOAuthProvider};
use mas_oidc_client::requests::authorization_code::AuthorizationRequestData;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    oauth2::OAuth2AuthorizationGrantRepository,
    upstream_oauth2::{UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository},
};
use minijinja::context;
use thiserror::Error;
use ulid::Ulid;

use super::{UpstreamSessionsCookie, cache::LazyProviderInfos, template::environment};
use crate::{
    impl_from_error_for_route, upstream_oauth2::cache::MetadataCache,
    views::shared::OptionalPostAuthAction,
};

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error("Provider not found")]
    ProviderNotFound,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error>),
}

impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);
impl_from_error_for_route!(mas_oidc_client::error::AuthorizationError);
impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            e @ Self::ProviderNotFound => {
                GenericError::new(StatusCode::NOT_FOUND, e).into_response()
            }
            Self::Internal(e) => InternalError::new(e).into_response(),
        }
    }
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.authorize.get",
    fields(upstream_oauth_provider.id = %provider_id),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(metadata_cache): State<MetadataCache>,
    mut repo: BoxRepository,
    State(url_builder): State<UrlBuilder>,
    State(http_client): State<reqwest::Client>,
    cookie_jar: CookieJar,
    Path(provider_id): Path<Ulid>,
    Query(query): Query<OptionalPostAuthAction>,
) -> Result<impl IntoResponse, RouteError> {
    // Load the session info from the cookie jar. We use this to know whether
    // the browser recently signed out, which we expose to the
    // `additional_authorization_parameters` templates as `logged_out` so that
    // operators can force a fresh prompt at the upstream provider. We consider
    // that we were logged out recently if we logged out within the last 5 minutes.
    let (session_info, cookie_jar) = cookie_jar.session_info();
    let logged_out = session_info
        .logged_out_at()
        .is_some_and(|t| t.signed_duration_since(clock.now()) < Duration::minutes(5));

    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .filter(UpstreamOAuthProvider::enabled)
        .ok_or(RouteError::ProviderNotFound)?;

    // First, discover the provider
    // This is done lazyly according to provider.discovery_mode and the various
    // endpoint overrides
    let mut lazy_metadata = LazyProviderInfos::new(&metadata_cache, &provider, &http_client);
    lazy_metadata.maybe_discover().await?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    let mut data = AuthorizationRequestData::new(
        provider.client_id.clone(),
        provider.scope.clone(),
        redirect_uri,
    );

    if let Some(response_mode) = provider.response_mode {
        data = data.with_response_mode(response_mode.into());
    }

    // Look up the downstream authorization grant once, if there is one, so
    // we can both (a) populate the MiniJinja template context for the
    // `additional_authorization_parameters` rendering and (b) keep the
    // `forward_login_hint` shortcut working for deployments that haven't
    // re-run config sync yet.
    let downstream_grant =
        if let Some(PostAuthAction::ContinueAuthorizationGrant { id }) = &query.post_auth_action {
            repo.oauth2_authorization_grant().lookup(*id).await?
        } else {
            None
        };

    let raw_parameters: BTreeMap<String, String> = downstream_grant
        .as_ref()
        .map(|grant| grant.raw_parameters.clone())
        .unwrap_or_default();

    // Back-compat: honour `forward_login_hint` as long as the operator
    // hasn't explicitly added a `login_hint` template entry to
    // `additional_authorization_parameters`. The CLI config sync will
    // also inject a template entry on the next sync, so this branch
    // mainly catches the moment between an upgrade and the next sync.
    if provider.forward_login_hint
        && !provider
            .additional_authorization_parameters
            .iter()
            .any(|(k, _)| k == "login_hint")
        && let Some(login_hint) = downstream_grant
            .as_ref()
            .and_then(|grant| grant.login_hint.clone())
    {
        data = data.with_login_hint(login_hint);
    }

    let data = if let Some(methods) = lazy_metadata.pkce_methods().await? {
        data.with_code_challenge_methods_supported(methods)
    } else {
        data
    };

    // Build an authorization request for it
    let (mut url, data) = mas_oidc_client::requests::authorization_code::build_authorization_url(
        lazy_metadata.authorization_endpoint().await?.clone(),
        data,
        &mut rng,
    )?;

    // Render the templated `additional_authorization_parameters` and
    // append the non-empty results to the URL query.
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in render_additional_authorization_parameters(
            provider.id,
            &provider.additional_authorization_parameters,
            &raw_parameters,
            logged_out,
        ) {
            pairs.append_pair(key, value.as_str());
        }
    }

    let session = repo
        .upstream_oauth_session()
        .add(
            &mut rng,
            &clock,
            &provider,
            data.state.clone(),
            data.code_challenge_verifier,
            data.nonce,
        )
        .await?;

    let cookie_jar = UpstreamSessionsCookie::load(&cookie_jar)
        .add(session.id, provider.id, data.state, query.post_auth_action)
        .save(cookie_jar, &clock);

    repo.save().await?;

    Ok((cookie_jar, Redirect::temporary(url.as_str())))
}

/// Render each `additional_authorization_parameters` template against
/// the raw downstream query parameters, dropping templates that render
/// to empty strings, and logging-and-skipping any that fail to render.
///
/// `logged_out` indicates whether the browser recently signed out (and has no
/// active session), and is exposed to the templates as the `logged_out`
/// variable.
fn render_additional_authorization_parameters<'a>(
    provider_id: Ulid,
    templates: &'a [(String, String)],
    raw_parameters: &BTreeMap<String, String>,
    logged_out: bool,
) -> impl Iterator<Item = (&'a str, String)> {
    let env = environment();
    let ctx = context! { params => raw_parameters, logged_out => logged_out };

    templates.iter().filter_map(move |(key, template)| {
        match env.render_str(template, &ctx).map(|v| v.trim().to_owned()) {
            Ok(value) if !value.is_empty() => Some((key.as_str(), value)),
            Ok(_) => {
                // Empty render — drop the parameter rather than forwarding
                // `?key=`.
                None
            }
            Err(error) => {
                tracing::warn!(
                    error = &error as &dyn std::error::Error,
                    upstream_oauth_provider.id = %provider_id,
                    parameter.key = %key,
                    "Failed to render upstream authorization parameter template",
                );
                None
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_data_model::{
        Clock, UlidExt, UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_router::{Route, SimpleRoute};
    use mas_storage::{RepositoryAccess, upstream_oauth2::UpstreamOAuthProviderParams};
    use oauth2_types::scope::{OPENID, Scope};
    use sqlx::PgPool;
    use ulid::Ulid;
    use zeroize::Zeroizing;

    use super::render_additional_authorization_parameters;
    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    fn params(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn renders_static_values_unchanged() {
        let templates = [("kc_idp_hint".to_owned(), "saml".to_owned())];
        let rendered = render_additional_authorization_parameters(
            Ulid::nil(),
            &templates,
            &params(&[]),
            false,
        )
        .collect::<Vec<_>>();
        assert_eq!(rendered, vec![("kc_idp_hint", "saml".to_owned())]);
    }

    #[test]
    fn renders_template_from_downstream_params() {
        let templates = [
            (
                "login_hint".to_owned(),
                "{{ params.login_hint }}".to_owned(),
            ),
            (
                "acr_values".to_owned(),
                "{{ params.acr_values }}".to_owned(),
            ),
        ];
        let rendered = render_additional_authorization_parameters(
            Ulid::nil(),
            &templates,
            &params(&[("login_hint", "alice"), ("acr_values", "mfa")]),
            false,
        )
        .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            vec![
                ("login_hint", "alice".to_owned()),
                ("acr_values", "mfa".to_owned()),
            ]
        );
    }

    #[test]
    fn drops_parameters_that_render_to_empty() {
        let templates = [
            (
                "login_hint".to_owned(),
                "{{ params.login_hint }}".to_owned(),
            ),
            ("kc_idp_hint".to_owned(), "saml".to_owned()),
        ];
        let rendered = render_additional_authorization_parameters(
            Ulid::nil(),
            &templates,
            &params(&[]),
            false,
        )
        .collect::<Vec<_>>();
        assert_eq!(rendered, vec![("kc_idp_hint", "saml".to_owned())]);
    }

    #[test]
    fn drops_failing_template_but_keeps_others() {
        let templates = [
            ("broken".to_owned(), "{{ params. }}".to_owned()),
            ("kc_idp_hint".to_owned(), "saml".to_owned()),
        ];
        let rendered = render_additional_authorization_parameters(
            Ulid::nil(),
            &templates,
            &params(&[]),
            false,
        )
        .collect::<Vec<_>>();
        assert_eq!(rendered, vec![("kc_idp_hint", "saml".to_owned())]);
    }

    #[test]
    fn renders_prompt_login_when_logged_out() {
        let templates = [(
            "prompt".to_owned(),
            "{% if logged_out %}login{% endif %}".to_owned(),
        )];
        let rendered =
            render_additional_authorization_parameters(Ulid::nil(), &templates, &params(&[]), true)
                .collect::<Vec<_>>();
        assert_eq!(rendered, vec![("prompt", "login".to_owned())]);
    }

    #[test]
    fn drops_prompt_when_not_logged_out() {
        let templates = [(
            "prompt".to_owned(),
            "{% if logged_out %}login{% endif %}".to_owned(),
        )];
        let rendered = render_additional_authorization_parameters(
            Ulid::nil(),
            &templates,
            &params(&[]),
            false,
        )
        .collect::<Vec<_>>();
        assert!(rendered.is_empty());
    }

    /// Create an upstream provider that forwards `prompt=login` only when the
    /// browser is logged out, using discovery disabled + an authorization
    /// endpoint override so the handler makes no network calls.
    async fn provider_with_logout_prompt(state: &TestState) -> Ulid {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        // Use `upsert` (not `add`) because only `upsert` persists
        // `additional_authorization_parameters` — which is what config sync
        // uses in production.
        let id = Ulid::from_datetime_with_rng(state.clock.now(), &mut rng);
        let provider = repo
            .upstream_oauth_provider()
            .upsert(
                &state.clock,
                id,
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
                    additional_authorization_parameters: vec![(
                        "prompt".to_owned(),
                        "{% if logged_out %}login{% endif %}".to_owned(),
                    )],
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

    async fn user_with_password(state: &TestState, username: &str, password: &str) {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.to_owned())
            .await
            .unwrap();
        let (version, hash) = state
            .password_manager
            .hash(&mut rng, Zeroizing::new(password.to_owned()))
            .await
            .unwrap();
        repo.user_password()
            .add(&mut rng, &state.clock, &user, version, hash, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
    }

    fn location(response: &hyper::Response<String>) -> String {
        response
            .headers()
            .get(LOCATION)
            .expect("missing Location header")
            .to_str()
            .unwrap()
            .to_owned()
    }

    /// End-to-end: after signing out, the upstream authorize redirect should
    /// carry `prompt=login`, while a browser that never signed out should not.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_prompt_login_after_logout(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let provider_id = provider_with_logout_prompt(&state).await;
        user_with_password(&state, "john", "hunter2").await;

        let authorize = mas_router::UpstreamOAuth2Authorize::new(provider_id)
            .path_and_query()
            .into_owned();

        // A brand-new browser (never logged out) should not get a `prompt`
        // parameter, because the `logged_out` template renders empty.
        let fresh = CookieHelper::new();
        let request = fresh.with_cookies(Request::get(authorize.as_str()).empty());
        let response = state.request(request).await;
        fresh.save_cookies(&response);
        response.assert_status(StatusCode::TEMPORARY_REDIRECT);
        assert!(
            !location(&response).contains("prompt="),
            "unexpected prompt parameter: {}",
            location(&response)
        );

        // Now log a user in, then sign out, reusing a single cookie jar.
        let cookies = CookieHelper::new();

        // Render the login page to obtain a CSRF token + cookie.
        let request = cookies.with_cookies(Request::get("/login").empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
            .to_owned();

        // Submit the login form.
        let request = cookies.with_cookies(Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        })));
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // While logged in, going through the authorize handler must NOT set
        // `prompt=login` — the browser has an active session.
        let request = cookies.with_cookies(Request::get(authorize.as_str()).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::TEMPORARY_REDIRECT);
        assert!(
            !location(&response).contains("prompt="),
            "unexpected prompt parameter while logged in: {}",
            location(&response)
        );

        // Sign out (the CSRF cookie is still valid within the fixed test clock).
        let request = cookies.with_cookies(Request::post(mas_router::Logout::PATH).form(
            serde_json::json!({
                "csrf": csrf_token,
            }),
        ));
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Now the authorize redirect should carry `prompt=login`.
        let request = cookies.with_cookies(Request::get(authorize.as_str()).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::TEMPORARY_REDIRECT);
        assert!(
            location(&response).contains("prompt=login"),
            "expected prompt=login after logout: {}",
            location(&response)
        );
    }

    /// Same as above, but the sign-out happens through the GraphQL
    /// `endBrowserSession` mutation on the current session.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_prompt_login_after_graphql_logout(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let provider_id = provider_with_logout_prompt(&state).await;
        user_with_password(&state, "john", "hunter2").await;

        let authorize = mas_router::UpstreamOAuth2Authorize::new(provider_id)
            .path_and_query()
            .into_owned();
        let cookies = CookieHelper::new();

        // Log in via the password flow to establish a browser session cookie.
        let request = cookies.with_cookies(Request::get("/login").empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
            .to_owned();
        let request = cookies.with_cookies(Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        })));
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Find the current browser session's GraphQL ID.
        let request = cookies.with_cookies(Request::post("/graphql").json(serde_json::json!({
            "query": "query { viewerSession { ... on BrowserSession { id } } }",
        })));
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let session_id = body["data"]["viewerSession"]["id"]
            .as_str()
            .expect("missing viewer session id")
            .to_owned();

        // End the current browser session, which makes the GraphQL HTTP layer
        // clear (and mark logged-out) the session cookie.
        let request = cookies.with_cookies(Request::post("/graphql").json(serde_json::json!({
            "query": "mutation($id: ID!) { endBrowserSession(input: { browserSessionId: $id }) { status } }",
            "variables": { "id": session_id },
        })));
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["data"]["endBrowserSession"]["status"].as_str(),
            Some("ENDED"),
            "{body:?}"
        );

        // The authorize redirect should now carry `prompt=login`.
        let request = cookies.with_cookies(Request::get(authorize.as_str()).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::TEMPORARY_REDIRECT);
        assert!(
            location(&response).contains("prompt=login"),
            "expected prompt=login after GraphQL logout: {}",
            location(&response)
        );
    }
}
