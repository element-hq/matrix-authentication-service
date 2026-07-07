// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::{Form, State},
    response::{IntoResponse, Redirect, Response},
};
use mas_axum_utils::{
    InternalError, RecordAsRequester, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, Clock, UpstreamOAuthProviderOnLogout};
use mas_oidc_client::requests::rp_initiated_logout::{LogoutData, build_end_session_url};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    upstream_oauth2::{UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository},
    user::BrowserSessionRepository,
};
use ulid::Ulid;
use url::Url;

use crate::{
    BoundActivityTracker,
    upstream_oauth2::{
        UpstreamLogoutCookie,
        cache::{LazyProviderInfos, MetadataCache},
    },
};

#[tracing::instrument(name = "handlers.views.logout.post", skip_all)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    State(metadata_cache): State<MetadataCache>,
    State(http_client): State<reqwest::Client>,
    activity_tracker: BoundActivityTracker,
    Form(form): Form<ProtectedForm<Option<PostAuthAction>>>,
) -> Result<Response, InternalError> {
    let form = cookie_jar.verify_form(&clock, form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    // If the browser session was established through an upstream provider that
    // wants RP-Initiated Logout, this holds the end-session URL to redirect to
    // and the cookie to stash the round-trip state in.
    let mut upstream_logout: Option<(Url, UpstreamLogoutCookie)> = None;

    if let Some(session_id) = session_info.current_session_id() {
        let maybe_session = repo.browser_session().lookup(session_id).await?;
        if let Some(session) = maybe_session
            && session.finished_at.is_none()
        {
            // Attribute this request (and its log line) to the user being
            // logged out.
            session.maybe_record_as_requester();

            activity_tracker
                .record_browser_session(&clock, &session)
                .await;

            // Before finishing the session, check whether we should also end
            // the upstream session. This is best-effort: any failure here must
            // not prevent the local logout from succeeding.
            upstream_logout = maybe_build_upstream_logout(
                &mut repo,
                &metadata_cache,
                &http_client,
                &mut rng,
                &url_builder,
                session_id,
                form.clone(),
            )
            .await;

            repo.browser_session().finish(&clock, session).await?;
        }
    }

    repo.save().await?;

    // We always want to clear out the session cookie, even if the session was
    // invalid
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended(clock.now()));

    // If we resolved an upstream end-session URL, stash the round-trip state
    // and redirect the browser there instead of the usual destination.
    if let Some((url, logout_cookie)) = upstream_logout {
        let cookie_jar = logout_cookie.save(cookie_jar);
        return Ok((cookie_jar, Redirect::temporary(url.as_str())).into_response());
    }

    let destination = if let Some(action) = form {
        action.go_next(&url_builder)
    } else {
        url_builder.redirect(&mas_router::Login::default())
    };

    Ok((cookie_jar, destination).into_response())
}

/// Try to build the upstream RP-Initiated Logout redirect for the given browser
/// session.
///
/// Returns `None` (and logs) on any condition that means we shouldn't or can't
/// do RP-Initiated Logout — the local logout still proceeds normally.
async fn maybe_build_upstream_logout(
    repo: &mut BoxRepository,
    metadata_cache: &MetadataCache,
    http_client: &reqwest::Client,
    rng: &mut BoxRng,
    url_builder: &UrlBuilder,
    session_id: Ulid,
    post_auth_action: Option<PostAuthAction>,
) -> Option<(Url, UpstreamLogoutCookie)> {
    // Find the upstream authorization session that established this browser
    // session, if any.
    let upstream_session = repo
        .upstream_oauth_session()
        .find_for_user_session(session_id)
        .await
        .inspect_err(|e| {
            tracing::warn!(
                error = e as &dyn std::error::Error,
                "Failed to look up upstream session for RP-initiated logout"
            );
        })
        .ok()??;

    let provider = repo
        .upstream_oauth_provider()
        .lookup(upstream_session.provider_id)
        .await
        .inspect_err(|e| {
            tracing::warn!(
                error = e as &dyn std::error::Error,
                "Failed to look up upstream provider for RP-initiated logout"
            );
        })
        .ok()??;

    // Only proceed if the provider opted into RP-Initiated Logout.
    if provider.on_logout != UpstreamOAuthProviderOnLogout::RpInitiatedLogout {
        return None;
    }

    // We need the raw id_token to use as `id_token_hint`.
    let id_token = upstream_session.id_token()?.to_owned();

    // Resolve the end-session endpoint (override, then discovery).
    let mut lazy_metadata = LazyProviderInfos::new(metadata_cache, &provider, http_client);
    let end_session_endpoint = match lazy_metadata.end_session_endpoint().await {
        Ok(Some(endpoint)) => endpoint,
        Ok(None) => {
            tracing::warn!(
                upstream_oauth_provider.id = %provider.id,
                "Provider is configured for RP-initiated logout but has no end_session_endpoint"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                upstream_oauth_provider.id = %provider.id,
                "Failed to resolve end_session_endpoint for RP-initiated logout"
            );
            return None;
        }
    };

    let logout_data = LogoutData {
        id_token_hint: Some(id_token),
        logout_hint: None,
        client_id: Some(provider.client_id.clone()),
        post_logout_redirect_uri: Some(url_builder.upstream_oauth_post_logout()),
        ui_locales: None,
    };

    let (url, state) = match build_end_session_url(end_session_endpoint, logout_data, rng) {
        Ok(res) => res,
        Err(e) => {
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                upstream_oauth_provider.id = %provider.id,
                "Failed to build end-session URL for RP-initiated logout"
            );
            return None;
        }
    };

    // `state` is always `Some` because we set a `post_logout_redirect_uri`.
    let state = state?;
    let cookie = UpstreamLogoutCookie::new(provider.id, state, post_auth_action);

    Some((url, cookie))
}

#[cfg(test)]
mod tests {
    use hyper::header::LOCATION;
    use mas_axum_utils::{SessionInfoExt, csrf::CsrfExt};
    use mas_data_model::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderOnLogout,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_router::SimpleRoute as _;
    use mas_storage::{
        RepositoryAccess,
        upstream_oauth2::{
            UpstreamOAuthLinkRepository, UpstreamOAuthProviderParams,
            UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository,
        },
        user::{BrowserSessionRepository, UserRepository},
    };
    use oauth2_types::scope::{OPENID, Scope};
    use sqlx::PgPool;
    use url::Url;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, TestState, setup};

    /// A provider with `on_logout = rp_initiated_logout` and an
    /// `end_session_endpoint` override should make `POST /logout` redirect the
    /// browser to the upstream end-session endpoint with the expected query
    /// parameters.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_logout_rp_initiated(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let end_session_endpoint = "https://upstream.example.com/end-session";

        // Provision a provider, a link, a browser session and a consumed
        // upstream session carrying an id_token.
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://upstream.example.com/".to_owned()),
                    human_name: Some("Example Ltd.".to_owned()),
                    brand_name: None,
                    scope: Scope::from_iter([OPENID]),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    jwks_uri_override: None,
                    // Discovery disabled so the override is used without any
                    // network access.
                    discovery_mode: UpstreamOAuthProviderDiscoveryMode::Disabled,
                    pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    on_logout: UpstreamOAuthProviderOnLogout::RpInitiatedLogout,
                    end_session_endpoint_override: Some(end_session_endpoint.parse().unwrap()),
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();

        let user = repo
            .user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "state".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();
        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "subject".to_owned(),
                None,
            )
            .await
            .unwrap();
        let session = repo
            .upstream_oauth_session()
            .complete_with_link(
                &state.clock,
                session,
                &link,
                Some("fake-id-token".to_owned()),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        repo.upstream_oauth_session()
            .consume(&state.clock, session, &browser_session)
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Set up the session cookie and a CSRF token
        let cookie_jar = state.cookie_jar();
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&state.clock, &mut rng);
        let cookie_jar = cookie_jar.set_session(&browser_session);
        cookies.import(cookie_jar);

        let request = hyper::Request::post(mas_router::Logout::PATH).form(serde_json::json!({
            "csrf": csrf_token.form_value(),
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);

        // We should be redirected to the upstream end-session endpoint
        assert!(
            response.status().is_redirection(),
            "expected a redirection, got {}",
            response.status()
        );
        let location = response
            .headers()
            .get(LOCATION)
            .expect("Location header")
            .to_str()
            .unwrap();
        let url = Url::parse(location).expect("valid Location URL");

        assert_eq!(
            format!(
                "{}://{}{}",
                url.scheme(),
                url.host_str().unwrap(),
                url.path()
            ),
            end_session_endpoint
        );

        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("id_token_hint").map(String::as_str),
            Some("fake-id-token")
        );
        assert_eq!(query.get("client_id").map(String::as_str), Some("client"));
        assert!(query.contains_key("post_logout_redirect_uri"));
        assert!(query.contains_key("state"));
    }

    /// With `on_logout` left at the default `do_nothing`, `POST /logout`
    /// behaves as before: it does not redirect to any upstream endpoint.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_logout_do_nothing(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar();
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&state.clock, &mut rng);
        let cookie_jar = cookie_jar.set_session(&browser_session);
        cookies.import(cookie_jar);

        let request = hyper::Request::post(mas_router::Logout::PATH).form(serde_json::json!({
            "csrf": csrf_token.form_value(),
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);

        assert!(response.status().is_redirection());
        let location = response
            .headers()
            .get(LOCATION)
            .expect("Location header")
            .to_str()
            .unwrap()
            .to_owned();
        // Not redirected to any external upstream endpoint
        assert!(!location.contains("upstream.example.com"));
    }
}
