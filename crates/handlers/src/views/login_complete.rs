// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Completion of a persisted login session.
//!
//! This is where a [`mas_router::PostAuthAction::ContinueLoginSession`] lands
//! once the user is (thought to be) authenticated. It is the authoritative
//! enforcement point for the login session's requested identity — the
//! deeplink analogue of what `/consent` is for an authorization grant: the
//! active browser session can have changed at any point of the flow, so the
//! trusted-target check is repeated here before the recorded post-auth action
//! (e.g. an account-management deeplink like a cross-signing reset) is
//! resumed.

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
};
use hyper::StatusCode;
use mas_axum_utils::{GenericError, InternalError, SessionInfoExt, cookies::CookieJar};
use mas_data_model::BoxClock;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{BoxRepository, user::LoginSessionRepository};
use mas_templates::{ErrorContext, Templates};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    BoundActivityTracker, PreferredLanguage, impl_from_error_for_route,
    views::shared::OptionalPostAuthAction,
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error("Login session not found")]
    NotFound,
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(serde_json::Error);

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        match self {
            Self::Internal(e) => InternalError::new(e).into_response(),
            e @ Self::NotFound => GenericError::new(StatusCode::NOT_FOUND, e).into_response(),
        }
    }
}

#[tracing::instrument(
    name = "handlers.views.login_complete.get",
    fields(login_session.id = %id),
    skip_all,
)]
pub(crate) async fn get(
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
) -> Result<Response, RouteError> {
    let login_session = repo
        .login_session()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound)?;

    let post_auth_action: Option<PostAuthAction> = login_session
        .post_auth_action
        .clone()
        .map(serde_json::from_value)
        .transpose()?;

    // Already completed: don't re-run any bookkeeping, just continue to
    // wherever the flow was going. This makes reloads and double-clicks
    // harmless.
    if login_session.completed_at.is_some() {
        let destination = OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder);
        return Ok((cookie_jar, destination).into_response());
    }

    if !login_session.is_valid(clock.now()) {
        let ctx = ErrorContext::new()
            .with_code("login_session_expired")
            .with_description("This login session expired.".to_owned())
            .with_language(&locale);

        let content = templates.render_error(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    let (session_info, cookie_jar) = cookie_jar.session_info();
    let maybe_session = session_info.load_active_session(&mut repo).await?;

    // Not (or no longer) authenticated: back to the login page, still
    // continuing this login session.
    let Some(session) = maybe_session else {
        let login =
            mas_router::Login::and_then(PostAuthAction::continue_login_session(login_session.id));
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    // Authoritative trusted-target check: never resume the deeplinked action
    // as a different user than the verified `id_token_hint` named. Only the
    // *trusted* case is enforced here; an untrusted `login_hint` stays
    // advisory (enforcing it would loop with the interstitial's
    // "continue as current" choice), mirroring the consent-side rule for
    // authorization grants.
    if login_session
        .target_user_id
        .is_some_and(|target| target != session.user.id)
    {
        repo.save().await?;
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::SelectAccount::new(
                PostAuthAction::continue_login_session(login_session.id),
            )),
        )
            .into_response());
    }

    // All good: mark the login session completed and continue the flow.
    repo.login_session()
        .complete(&clock, login_session, &session)
        .await?;
    repo.save().await?;

    let destination = OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder);
    Ok((cookie_jar, destination).into_response())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::Duration;
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_data_model::Clock;
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_jose::{
        claims,
        jwt::{JsonWebSignatureHeader, Jwt},
    };
    use mas_storage::user::{LoginSessionRepository, UserPasswordRepository};
    use serde_json::Value;
    use sqlx::PgPool;
    use ulid::Ulid;
    use zeroize::Zeroizing;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    /// Provision a user with a password and a browser session whose
    /// most-recent authentication is that password.
    async fn user_with_password_session(
        state: &TestState,
        username: &str,
    ) -> (mas_data_model::User, mas_data_model::BrowserSession) {
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
        let user_password = repo
            .user_password()
            .add(&mut rng, &state.clock, &user, version, hash, None)
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.browser_session()
            .authenticate_with_password(&mut rng, &state.clock, &browser_session, &user_password)
            .await
            .unwrap();
        repo.save().await.unwrap();
        (user, browser_session)
    }

    /// Log in as the given user via `POST /login`, returning a cookie helper
    /// holding the active session cookie.
    async fn login(state: &TestState, username: &str) -> CookieHelper {
        let cookies = CookieHelper::new();

        let request = cookies.with_cookies(Request::get("/login").empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        let csrf_token = extract_csrf(response.body());

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

    fn extract_csrf(body: &str) -> String {
        body.split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
            .to_owned()
    }

    /// Mint a MAS-signed ID-token-shaped JWT for the given subject (and
    /// optional sid), with an already-expired `exp`.
    fn mint_hint(state: &TestState, sub: &str, sid: Option<&str>) -> String {
        let issuer = state.url_builder.oidc_issuer().to_string();
        let mut payload: HashMap<String, Value> = HashMap::new();
        claims::ISS.insert(&mut payload, issuer).unwrap();
        claims::SUB.insert(&mut payload, sub.to_owned()).unwrap();
        if let Some(sid) = sid {
            claims::SID.insert(&mut payload, sid.to_owned()).unwrap();
        }
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

    fn location(response: &hyper::Response<String>) -> String {
        response
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn login_session_id(location: &str) -> Ulid {
        location
            .split_once('?')
            .expect("expected a query string")
            .1
            .split('&')
            .find_map(|pair| pair.strip_prefix("id="))
            .expect("expected an `id` query parameter")
            .parse()
            .unwrap()
    }

    /// Logged out, a trusted deeplink hint whose target last used a password:
    /// the whole flow — welcome-back page, password POST, completion — lands
    /// back on /account/ and marks the login session completed.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deeplink_welcome_back_password(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let (alice, alice_session) = user_with_password_session(&state, "alice").await;
        let hint = mint_hint(&state, &alice.sub, Some(&alice_session.id.to_string()));

        // The deeplink redirects to /login continuing a fresh login session.
        let url = format!("/account/?org.matrix.msc4198.id_token_hint={hint}");
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let login_url = location(&response);
        assert!(
            login_url.starts_with("/login") && login_url.contains("kind=continue_login_session"),
            "expected /login continuing a login session, got {login_url}"
        );
        let session_id = login_session_id(&login_url);

        // /login renders the welcome-back page for alice.
        let request = cookies.with_cookies(Request::get(&login_url).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(
            body.contains("Confirm it's you"),
            "expected the welcome-back page, body: {body}"
        );
        let csrf_token = extract_csrf(body);

        // Posting the password continues to /login/complete/{id}.
        let request = cookies.with_cookies(Request::post(&login_url).form(serde_json::json!({
            "csrf": csrf_token,
            "username": "alice",
            "password": "hunter2",
        })));
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let complete_url = location(&response);
        assert_eq!(complete_url, format!("/login/complete/{session_id}"));

        // Completion re-checks the identity, marks the session completed and
        // lands on /account/.
        let request = cookies.with_cookies(Request::get(&complete_url).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/account/");

        let mut repo = state.repository().await.unwrap();
        let login_session = repo
            .login_session()
            .lookup(session_id)
            .await
            .unwrap()
            .unwrap();
        assert!(login_session.completed_at.is_some());
        assert!(login_session.user_session_id.is_some());
        assert_eq!(login_session.target_user_id, Some(alice.id));
    }

    /// Logged in as bob, a trusted deeplink hint for alice: the interstitial
    /// is shown, names alice, and offers no continue-as-current.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deeplink_trusted_mismatch(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let (alice, _) = user_with_password_session(&state, "alice").await;
        user_with_password_session(&state, "bob").await;
        let cookies = login(&state, "bob").await;

        let hint = mint_hint(&state, &alice.sub, None);
        let url = format!("/account/?org.matrix.msc4198.id_token_hint={hint}");
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let selection_url = location(&response);
        assert!(
            selection_url.contains("/account-selection")
                && selection_url.contains("kind=continue_login_session"),
            "expected account-selection continuing a login session, got {selection_url}"
        );

        let request = cookies.with_cookies(Request::get(&selection_url).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(
            body.contains("@alice:"),
            "should name the trusted target, body: {body}"
        );
        assert!(
            !body.contains("Continue as bob"),
            "trusted mismatch must not offer continue-as-current, body: {body}"
        );

        // A crafted `continue` POST must not complete the flow.
        let csrf_token = extract_csrf(body);
        let request = cookies.with_cookies(Request::post(&selection_url).form(serde_json::json!({
            "csrf": csrf_token,
            "action": "continue",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let dest = location(&response);
        assert!(
            dest.contains("/account-selection"),
            "a trusted `continue` must bounce back to account-selection, got {dest}"
        );
    }

    /// Logged in as bob, an untrusted deeplink `login_hint` for alice: the
    /// interstitial offers continue-as-current, and choosing it completes the
    /// flow as bob.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deeplink_untrusted_continue(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        user_with_password_session(&state, "bob").await;
        let cookies = login(&state, "bob").await;

        let url = "/account/?org.matrix.msc4198.login_hint=mxid%3A%40alice%3Aexample.com";
        let request = cookies.with_cookies(Request::get(url).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let selection_url = location(&response);
        assert!(
            selection_url.contains("/account-selection"),
            "expected account-selection, got {selection_url}"
        );

        let request = cookies.with_cookies(Request::get(&selection_url).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(
            body.contains("Continue as bob"),
            "untrusted mismatch must offer continue-as-current, body: {body}"
        );

        let csrf_token = extract_csrf(body);
        let request = cookies.with_cookies(Request::post(&selection_url).form(serde_json::json!({
            "csrf": csrf_token,
            "action": "continue",
        })));
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let complete_url = location(&response);
        assert!(
            complete_url.starts_with("/login/complete/"),
            "continue should land on the completion handler, got {complete_url}"
        );

        let request = cookies.with_cookies(Request::get(&complete_url).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/account/");
    }

    /// Logged in as alice with a trusted hint for alice: no interstitial, the
    /// app renders directly and no login session is created.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deeplink_match_renders_app(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let (alice, _) = user_with_password_session(&state, "alice").await;
        let cookies = login(&state, "alice").await;

        let hint = mint_hint(&state, &alice.sub, None);
        let url = format!("/account/?org.matrix.msc4198.id_token_hint={hint}");
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
    }

    /// An expired login session renders an error page instead of continuing.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_complete_expired(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let (alice, _) = user_with_password_session(&state, "alice").await;
        let hint = mint_hint(&state, &alice.sub, None);
        let url = format!("/account/?org.matrix.msc4198.id_token_hint={hint}");
        let response = state.request(Request::get(&url).empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let session_id = login_session_id(&location(&response));

        state.clock.advance(Duration::minutes(31));

        let response = state
            .request(Request::get(format!("/login/complete/{session_id}")).empty())
            .await;
        response.assert_status(StatusCode::OK);
        assert!(
            response.body().contains("expired"),
            "expected the expired error page, body: {}",
            response.body()
        );
    }

    /// The completion handler re-checks the trusted target against the
    /// now-active session: logging in as bob out-of-band mid-flow diverts to
    /// the interstitial rather than resuming the deeplink as bob.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_complete_recheck_mismatch(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let (alice, _) = user_with_password_session(&state, "alice").await;
        user_with_password_session(&state, "bob").await;

        // Start the deeplink flow logged out: creates the login session.
        let cookies = CookieHelper::new();
        let hint = mint_hint(&state, &alice.sub, None);
        let url = format!("/account/?org.matrix.msc4198.id_token_hint={hint}");
        let request = cookies.with_cookies(Request::get(&url).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);
        let session_id = login_session_id(&location(&response));

        // Log in as bob through a plain login, NOT continuing the flow.
        let request = cookies.with_cookies(Request::get("/login").empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        let csrf_token = extract_csrf(response.body());
        let request = cookies.with_cookies(Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "bob",
            "password": "hunter2",
        })));
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Resuming the flow must not complete it as bob.
        let request =
            cookies.with_cookies(Request::get(format!("/login/complete/{session_id}")).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let dest = location(&response);
        assert!(
            dest.contains("/account-selection"),
            "completion as the wrong user must divert to account-selection, got {dest}"
        );

        let mut repo = state.repository().await.unwrap();
        let login_session = repo
            .login_session()
            .lookup(session_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            login_session.completed_at.is_none(),
            "the login session must not be completed as the wrong user"
        );
    }
}
