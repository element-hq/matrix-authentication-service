// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! The account-mismatch interstitial.
//!
//! Shown while continuing an authorization grant whose requested identity (a
//! verified `id_token_hint` target, or an untrusted `login_hint`) doesn't match
//! the active browser session. It is always scoped to a grant — never reachable
//! as a standalone endpoint — which keeps it from being a generic phishing
//! surface.

use std::sync::Arc;

use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::Query;
use hyper::StatusCode;
use mas_axum_utils::{
    GenericError, InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{AuthorizationGrantStage, BoxClock, BoxRng};
use mas_matrix::HomeserverConnection;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository, oauth2::OAuth2AuthorizationGrantRepository, user::BrowserSessionRepository,
};
use mas_templates::{SelectAccountContext, TemplateContext, Templates};
use oauth2_types::errors::{ClientError, ClientErrorCode};
use serde::Deserialize;
use thiserror::Error;
use ulid::Ulid;

use super::{callback::CallbackDestination, id_token_hint::session_matches_requested_identity};
use crate::{BoundActivityTracker, PreferredLanguage, impl_from_error_for_route};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Csrf(#[from] mas_axum_utils::csrf::CsrfError),

    #[error("Authorization grant not found")]
    GrantNotFound,

    #[error("Authorization grant {0} already used")]
    GrantNotPending(Ulid),
}

impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(super::callback::IntoCallbackDestinationError);
impl_from_error_for_route!(super::callback::CallbackDestinationError);

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        match self {
            Self::Internal(e) => InternalError::new(e).into_response(),
            e @ Self::GrantNotFound => GenericError::new(StatusCode::NOT_FOUND, e).into_response(),
            e @ Self::GrantNotPending(_) => {
                GenericError::new(StatusCode::CONFLICT, e).into_response()
            }
            e @ Self::Csrf(_) => GenericError::new(StatusCode::BAD_REQUEST, e).into_response(),
        }
    }
}

/// Build the requested-identity display string and trust flag for the grant.
///
/// For a trusted target we look up the resolved user (allowed — the hint was
/// cryptographically verified) and show its mxid. For an untrusted `login_hint`
/// we echo the client-supplied string verbatim, never looking it up.
async fn requested_identity(
    repo: &mut BoxRepository,
    homeserver: &dyn HomeserverConnection,
    grant: &mas_data_model::AuthorizationGrant,
) -> Result<Option<(String, bool)>, RouteError> {
    if let Some(target) = grant.target_user_id {
        let user = repo.user().lookup(target).await?;
        return Ok(user.map(|user| (homeserver.mxid(&user.username), true)));
    }

    Ok(grant
        .login_hint
        .clone()
        .map(|hint| (login_hint_display(&hint), false)))
}

/// Turn a raw `login_hint` into something friendlier to echo, while still being
/// purely the client's own input (no MAS-side lookup).
fn login_hint_display(hint: &str) -> String {
    hint.strip_prefix("mxid:").unwrap_or(hint).to_owned()
}

#[tracing::instrument(
    name = "handlers.oauth2.authorization.select_account.get",
    fields(grant.id = tracing::field::Empty),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    Query(params): Query<mas_router::SelectAccount>,
) -> Result<Response, RouteError> {
    let action = params.post_auth_action();
    let PostAuthAction::ContinueAuthorizationGrant { id: grant_id } = *action else {
        // Other flows (device-code, manage-account) don't populate a requested
        // identity yet, so the account-selection screen is a no-op passthrough
        // for them; just continue the flow.
        return Ok((cookie_jar, action.go_next(&url_builder)).into_response());
    };
    tracing::Span::current().record("grant.id", tracing::field::display(grant_id));

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let maybe_session = session_info.load_active_session(&mut repo).await?;

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending(grant.id));
    }

    // No active session: nothing to mismatch against, send them to login
    // continuing the grant.
    let Some(session) = maybe_session else {
        let login = mas_router::Login::and_continue_grant(grant_id);
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // Defensive: if the session actually matches (or there is no constraint),
    // don't show the interstitial — go straight to consent. Entry routing
    // should already prevent landing here on a match.
    if session_matches_requested_identity(&mut repo, homeserver.homeserver(), &grant, &session)
        .await?
    {
        repo.save().await?;
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::Consent(grant_id)),
        )
            .into_response());
    }

    let Some((requested, trusted)) = requested_identity(&mut repo, &*homeserver, &grant).await?
    else {
        // Only reachable when a trusted target vanished since authorize time
        // (an absent hint counted as a match above). Per OIDC Core the grant
        // can never be fulfilled as a different user, so return
        // `login_required` to the client rather than redirecting to consent,
        // which would divert straight back here.
        let callback_destination = CallbackDestination::try_from(&grant)?;
        repo.save().await?;
        let response = callback_destination.go(
            &templates,
            &locale,
            ClientError::from(ClientErrorCode::LoginRequired),
        )?;
        return Ok((cookie_jar, response).into_response());
    };

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let current_username = session.user.username.clone();

    repo.save().await?;

    let ctx = SelectAccountContext::new(requested, trusted, current_username)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_select_account(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub(crate) enum FormAction {
    /// Sign in as the requested account (sign out the current one).
    Switch,
    /// Continue as the current account (untrusted hint only).
    Continue,
    /// Abandon the flow and return an error to the client.
    Cancel,
}

#[tracing::instrument(
    name = "handlers.oauth2.authorization.select_account.post",
    fields(grant.id = tracing::field::Empty),
    skip_all,
)]
pub(crate) async fn post(
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    Query(params): Query<mas_router::SelectAccount>,
    Form(form): Form<ProtectedForm<FormAction>>,
) -> Result<Response, RouteError> {
    let action = params.post_auth_action();
    let PostAuthAction::ContinueAuthorizationGrant { id: grant_id } = *action else {
        // Other flows (device-code, manage-account) don't populate a requested
        // identity yet, so the account-selection screen is a no-op passthrough
        // for them; just continue the flow.
        return Ok((cookie_jar, action.go_next(&url_builder)).into_response());
    };
    tracing::Span::current().record("grant.id", tracing::field::display(grant_id));

    let form = cookie_jar.verify_form(&clock, form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending(grant.id));
    }

    match form {
        FormAction::Continue => {
            // "Continue as current" only exists for an untrusted hint. For a
            // trusted target (a verified `id_token_hint`) OIDC Core forbids
            // returning a token for a different user, and the screen never
            // offers this action — so a crafted POST must not be allowed to
            // complete the grant as the current account. Divert back to the
            // account-selection screen instead of proceeding to consent.
            if grant.target_user_id.is_some() {
                repo.save().await?;
                return Ok((
                    cookie_jar,
                    url_builder.redirect(&mas_router::SelectAccount::new(action.clone())),
                )
                    .into_response());
            }

            // Untrusted hint only: the user explicitly chooses to keep their
            // current account. Proceed to consent (it re-enforces the match).
            repo.save().await?;
            Ok((
                cookie_jar,
                url_builder.redirect(&mas_router::Consent(grant_id)),
            )
                .into_response())
        }

        FormAction::Switch => {
            // Sign out the current session (mirroring logout), then send the
            // user to login continuing the grant. Slice 1's welcome-back handles
            // a trusted target; a generic pre-fill handles the untrusted case,
            // for which we carry the original `login_hint` along.
            if let Some(session_id) = session_info.current_session_id() {
                let maybe_session = repo.browser_session().lookup(session_id).await?;
                if let Some(session) = maybe_session
                    && session.finished_at.is_none()
                {
                    activity_tracker
                        .record_browser_session(&clock, &session)
                        .await;
                    repo.browser_session().finish(&clock, session).await?;
                }
            }

            repo.save().await?;

            let cookie_jar =
                cookie_jar.update_session_info(&session_info.mark_session_ended(clock.now()));

            let mut login = mas_router::Login::and_continue_grant(grant_id);
            // Only the untrusted case needs the hint forwarded; for a trusted
            // target the resolved identity is already on the grant.
            if grant.target_user_id.is_none()
                && let Some(login_hint) = grant.login_hint
            {
                login = login.with_login_hint(login_hint);
            }

            Ok((cookie_jar, url_builder.redirect(&login)).into_response())
        }

        FormAction::Cancel => {
            // Bail out: return an `access_denied` error to the client.
            let callback_destination = CallbackDestination::try_from(&grant)?;
            repo.save().await?;
            let response = callback_destination.go(
                &templates,
                &locale,
                ClientError::from(ClientErrorCode::AccessDenied),
            )?;
            Ok((cookie_jar, response).into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::Duration;
    use hyper::{
        Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };
    use mas_data_model::Clock;
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_jose::{
        claims,
        jwt::{JsonWebSignatureHeader, Jwt},
    };
    use mas_router::SimpleRoute;
    use mas_storage::user::{UserPasswordRepository, UserRepository};
    use serde_json::Value;
    use sqlx::PgPool;
    use zeroize::Zeroizing;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    /// Register a public `OAuth2` client we can run an authorization flow
    /// against.
    async fn provision_client(state: &TestState) -> String {
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/redirect"],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "none",
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let response: oauth2_types::registration::ClientRegistrationResponse = response.json();
        response.client_id
    }

    /// Provision a user with a password.
    async fn user_with_password(state: &TestState, username: &str) -> mas_data_model::User {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.to_owned())
            .await
            .unwrap();
        let (version, hash) = state
            .password_manager
            .hash(&mut rng, Zeroizing::new("hunter2".to_owned()))
            .await
            .unwrap();
        repo.user_password()
            .add(&mut rng, &state.clock, &user, version, hash, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        user
    }

    /// Log in as the given user via `POST /login`, returning a cookie helper
    /// holding the active session cookie.
    async fn login(state: &TestState, username: &str) -> CookieHelper {
        let cookies = CookieHelper::new();

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
            "username": username,
            "password": "hunter2",
        })));
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        cookies
    }

    /// Mint a MAS-signed ID-token-shaped JWT for the given subject, with an
    /// already-expired `exp` (a realistic stale `id_token_hint`).
    fn mint_hint(state: &TestState, sub: &str) -> String {
        let issuer = state.url_builder.oidc_issuer().to_string();
        let mut payload: HashMap<String, Value> = HashMap::new();
        claims::ISS.insert(&mut payload, issuer).unwrap();
        claims::SUB.insert(&mut payload, sub.to_owned()).unwrap();
        claims::IAT
            .insert(&mut payload, state.clock.now() - Duration::hours(2))
            .unwrap();
        claims::EXP
            .insert(&mut payload, state.clock.now() - Duration::hours(1))
            .unwrap();

        let key = state
            .key_store
            .signing_key_for_algorithm(&JsonWebSignatureAlg::Rs256)
            .unwrap();
        let signer = key
            .params()
            .signing_key_for_alg(&JsonWebSignatureAlg::Rs256)
            .unwrap();
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);
        let jwt: Jwt<'static, _> =
            Jwt::sign_with_rng(&mut state.rng(), header, payload, &signer).unwrap();
        jwt.into_string()
    }

    fn authorize_url(client_id: &str, extra: &str) -> String {
        format!(
            "{}?response_type=code&client_id={client_id}&redirect_uri=https://example.com/redirect&scope=openid&state=somestate&{extra}",
            mas_router::OAuth2AuthorizationEndpoint::PATH,
        )
    }

    /// Find the grant id the authorize handler redirected to, regardless of
    /// whether it landed on consent or the account-selection screen.
    fn redirect_path(response: &hyper::Response<String>) -> String {
        response
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    /// Logged in as bob, a trusted hint for alice → account-selection screen
    /// naming alice, with NO "continue as bob" option.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_trusted_mismatch_no_continue(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let alice = user_with_password(&state, "alice").await;
        user_with_password(&state, "bob").await;
        let client_id = provision_client(&state).await;
        let cookies = login(&state, "bob").await;

        let hint = mint_hint(&state, &alice.sub);
        let url = authorize_url(&client_id, &format!("id_token_hint={hint}"));
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let location = redirect_path(&response);
        assert!(
            location.contains("/account-selection"),
            "expected account-selection, got {location}"
        );

        // Follow the redirect to render the interstitial.
        let request = cookies.with_cookies(Request::get(&location).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        let body = response.body();
        assert!(
            body.contains("@alice:"),
            "should name the trusted target alice, body: {body}"
        );
        assert!(
            !body.contains("Continue as bob"),
            "trusted mismatch must not offer continue-as-current, body: {body}"
        );
    }

    /// Logged in as bob, an untrusted `login_hint` for alice →
    /// account-selection screen WITH a "continue as bob" option; choosing to
    /// continue redirects to consent.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_untrusted_mismatch_continue(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        user_with_password(&state, "bob").await;
        let client_id = provision_client(&state).await;
        let cookies = login(&state, "bob").await;

        let url = authorize_url(&client_id, "login_hint=mxid%3A%40alice%3Aexample.com");
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let location = redirect_path(&response);
        assert!(
            location.contains("/account-selection"),
            "expected account-selection, got {location}"
        );

        let request = cookies.with_cookies(Request::get(&location).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(
            body.contains("Continue as bob"),
            "untrusted mismatch must offer continue-as-current, body: {body}"
        );
        // Echoes the client-supplied hint.
        assert!(
            body.contains("@alice:example.com"),
            "should echo the login_hint, body: {body}"
        );

        // Extract CSRF and POST "continue".
        let csrf_token = body
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
            .to_owned();
        let request = cookies.with_cookies(Request::post(&location).form(serde_json::json!({
            "csrf": csrf_token,
            "action": "continue",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert!(
            redirect_path(&response).contains("/consent/"),
            "continue-as-current should land on consent"
        );
    }

    /// Logged in as alice, a trusted hint for alice (a match) → straight to
    /// consent, no interstitial.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_match_goes_to_consent(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let alice = user_with_password(&state, "alice").await;
        let client_id = provision_client(&state).await;
        let cookies = login(&state, "alice").await;

        let hint = mint_hint(&state, &alice.sub);
        let url = authorize_url(&client_id, &format!("id_token_hint={hint}"));
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert!(
            redirect_path(&response).contains("/consent/"),
            "a matching session should skip straight to consent"
        );
    }

    /// "Sign in as target" POST clears the session cookie and redirects to
    /// /login continuing the grant.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_switch_clears_session(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let alice = user_with_password(&state, "alice").await;
        user_with_password(&state, "bob").await;
        let client_id = provision_client(&state).await;
        let cookies = login(&state, "bob").await;

        let hint = mint_hint(&state, &alice.sub);
        let url = authorize_url(&client_id, &format!("id_token_hint={hint}"));
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        let location = redirect_path(&response);

        let request = cookies.with_cookies(Request::get(&location).empty());
        let response = state.request(request).await;
        let body = response.body();
        let csrf_token = body
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
            .to_owned();

        let request = cookies.with_cookies(Request::post(&location).form(serde_json::json!({
            "csrf": csrf_token,
            "action": "switch",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        // It should redirect to /login continuing the grant...
        let dest = redirect_path(&response);
        assert!(dest.starts_with("/login"), "expected /login, got {dest}");

        // ...and forget the session cookie (Set-Cookie with an emptied/expired
        // session jar).
        let set_cookie = response
            .headers()
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            set_cookie.contains("session"),
            "the switch response should rewrite the session cookie, got: {set_cookie}"
        );
    }

    /// Extract the grant id from the `id` query parameter of an
    /// `/account-selection?kind=...&id=<ULID>` location.
    fn grant_id_from_selection(location: &str) -> &str {
        let query = location
            .split_once('?')
            .expect("expected an account-selection location with a query")
            .1;
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix("id="))
            .expect("expected an `id` query parameter")
    }

    /// Trusted mismatch: hitting `/consent/{grant_id}` directly while logged in
    /// as the wrong user (session=bob, target=alice) must NOT render consent —
    /// it diverts back to the account-selection screen.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_consent_trusted_mismatch_diverts(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let alice = user_with_password(&state, "alice").await;
        user_with_password(&state, "bob").await;
        let client_id = provision_client(&state).await;
        let cookies = login(&state, "bob").await;

        let hint = mint_hint(&state, &alice.sub);
        let url = authorize_url(&client_id, &format!("id_token_hint={hint}"));
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        let location = redirect_path(&response);
        let grant_id = grant_id_from_selection(&location);

        // Hit consent directly, bypassing the interstitial.
        let consent = format!("/consent/{grant_id}");
        let request = cookies.with_cookies(Request::get(&consent).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let dest = redirect_path(&response);
        assert!(
            dest.contains("/account-selection"),
            "trusted mismatch at consent must divert to account-selection, got {dest}"
        );
    }

    /// Trusted grant + POST `action=continue` to the account-selection screen
    /// must be rejected: it must NOT reach consent (the screen never offers
    /// this action for a trusted target).
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_trusted_continue_rejected(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let alice = user_with_password(&state, "alice").await;
        user_with_password(&state, "bob").await;
        let client_id = provision_client(&state).await;
        let cookies = login(&state, "bob").await;

        let hint = mint_hint(&state, &alice.sub);
        let url = authorize_url(&client_id, &format!("id_token_hint={hint}"));
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        let location = redirect_path(&response);

        // Render the interstitial to grab a valid CSRF token.
        let request = cookies.with_cookies(Request::get(&location).empty());
        let response = state.request(request).await;
        let body = response.body();
        let csrf_token = body
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
            .to_owned();

        // A crafted `continue` POST with a valid CSRF token must not complete
        // the trusted grant.
        let request = cookies.with_cookies(Request::post(&location).form(serde_json::json!({
            "csrf": csrf_token,
            "action": "continue",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let dest = redirect_path(&response);
        assert!(
            !dest.contains("/consent/"),
            "a trusted `continue` must not reach consent, got {dest}"
        );
        assert!(
            dest.contains("/account-selection"),
            "a trusted `continue` should be sent back to account-selection, got {dest}"
        );
    }

    /// Untrusted mismatch (`login_hint` only) at consent must still proceed —
    /// it must NOT be diverted (guards against an interstitial ↔ consent
    /// loop).
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_consent_untrusted_mismatch_proceeds(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        user_with_password(&state, "bob").await;
        let client_id = provision_client(&state).await;
        let cookies = login(&state, "bob").await;

        let url = authorize_url(&client_id, "login_hint=mxid%3A%40alice%3Aexample.com");
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        let location = redirect_path(&response);
        let grant_id = grant_id_from_selection(&location);

        let consent = format!("/consent/{grant_id}");
        let request = cookies.with_cookies(Request::get(&consent).empty());
        let response = state.request(request).await;
        // Renders consent (200) rather than diverting back to account-selection.
        response.assert_status(StatusCode::OK);
        let dest = response.headers().get(LOCATION);
        assert!(
            dest.is_none(),
            "untrusted mismatch at consent must not be diverted"
        );
    }

    /// Match (session=alice, target=alice) at consent proceeds as before:
    /// the authorize handler sends a matching session straight to consent.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_consent_match_proceeds(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let alice = user_with_password(&state, "alice").await;
        let client_id = provision_client(&state).await;
        let cookies = login(&state, "alice").await;

        let hint = mint_hint(&state, &alice.sub);
        let url = authorize_url(&client_id, &format!("id_token_hint={hint}"));
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        let location = redirect_path(&response);
        assert!(
            location.contains("/consent/"),
            "a matching session should land on consent, got {location}"
        );

        let request = cookies.with_cookies(Request::get(&location).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let dest = response.headers().get(LOCATION);
        assert!(dest.is_none(), "a matching session must render consent");
    }

    /// "Cancel" POST returns an `access_denied` error to the client callback.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_cancel_access_denied(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let alice = user_with_password(&state, "alice").await;
        user_with_password(&state, "bob").await;
        let client_id = provision_client(&state).await;
        let cookies = login(&state, "bob").await;

        let hint = mint_hint(&state, &alice.sub);
        let url = authorize_url(&client_id, &format!("id_token_hint={hint}"));
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        let location = redirect_path(&response);

        let request = cookies.with_cookies(Request::get(&location).empty());
        let response = state.request(request).await;
        let body = response.body();
        let csrf_token = body
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
            .to_owned();

        let request = cookies.with_cookies(Request::post(&location).form(serde_json::json!({
            "csrf": csrf_token,
            "action": "cancel",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let dest = redirect_path(&response);
        assert!(
            dest.starts_with("https://example.com/redirect")
                && dest.contains("error=access_denied"),
            "cancel should redirect to the client callback with access_denied, got {dest}"
        );
        assert!(
            dest.contains("state=somestate"),
            "cancel callback should carry the grant state, got {dest}"
        );
    }
}
