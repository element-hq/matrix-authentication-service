// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! OIDC RP-Initiated Logout towards the upstream provider.
//!
//! When a user logs out of MAS and their browser session was established
//! through an upstream OIDC provider configured with
//! `on_logout = rp_initiated_logout`, MAS redirects the browser to the
//! upstream provider's `end_session_endpoint`. Once the upstream session is
//! ended, the provider redirects back to the [`get`] handler here, which
//! validates the round-tripped `state` and sends the user to their final
//! destination.

use axum::{extract::State, response::IntoResponse};
use axum_extra::extract::Query;
use mas_axum_utils::cookies::CookieJar;
use mas_router::{PostAuthAction, UrlBuilder};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Name of the cookie holding the pending upstream logout state
static COOKIE_NAME: &str = "upstream-oauth2-logout";

/// Short-lived cookie stashing the state of a pending RP-Initiated Logout, so
/// the [`get`] return handler can validate it and resume the post-logout
/// action.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct UpstreamLogoutCookie {
    /// The upstream provider we redirected the browser to
    pub provider: Ulid,

    /// The random `state` value we sent in the end-session request
    pub state: String,

    /// Where to send the user once logout completes
    pub post_auth_action: Option<PostAuthAction>,
}

impl UpstreamLogoutCookie {
    pub(crate) fn new(
        provider: Ulid,
        state: String,
        post_auth_action: Option<PostAuthAction>,
    ) -> Self {
        Self {
            provider,
            state,
            post_auth_action,
        }
    }

    pub(crate) fn load(cookie_jar: &CookieJar) -> Option<Self> {
        match cookie_jar.load(COOKIE_NAME) {
            Ok(Some(cookie)) => Some(cookie),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("Invalid upstream logout cookie: {}", e);
                None
            }
        }
    }

    pub(crate) fn save(&self, cookie_jar: CookieJar) -> CookieJar {
        cookie_jar.save(COOKIE_NAME, self, false)
    }

    pub(crate) fn clear(cookie_jar: CookieJar) -> CookieJar {
        cookie_jar.remove(COOKIE_NAME)
    }
}

/// Query parameters the upstream provider appends to the
/// `post_logout_redirect_uri`.
#[derive(Deserialize)]
pub(crate) struct QueryParams {
    #[serde(default)]
    state: Option<String>,
}

/// `GET /upstream/post-logout`
///
/// The return route the upstream provider redirects to after ending its
/// session. Validates the round-tripped `state` against the logout cookie and
/// resumes the stashed [`PostAuthAction`]. On missing or mismatched state, it
/// soft-fails to the login page (no error page).
#[tracing::instrument(name = "handlers.upstream_oauth2.post_logout.get", skip_all)]
pub(crate) async fn get(
    State(url_builder): State<UrlBuilder>,
    cookie_jar: CookieJar,
    Query(params): Query<QueryParams>,
) -> impl IntoResponse {
    let cookie = UpstreamLogoutCookie::load(&cookie_jar);
    // Always clear the cookie, whether or not it validates.
    let cookie_jar = UpstreamLogoutCookie::clear(cookie_jar);

    let post_auth_action = match (cookie, params.state) {
        (Some(cookie), Some(state)) if cookie.state == state => cookie.post_auth_action,
        _ => {
            tracing::warn!("Upstream post-logout state missing or mismatched, ignoring");
            None
        }
    };

    let destination = if let Some(action) = post_auth_action {
        action.go_next(&url_builder)
    } else {
        url_builder.redirect(&mas_router::Login::default())
    };

    (cookie_jar, destination)
}

#[cfg(test)]
mod tests {
    use hyper::header::LOCATION;
    use mas_router::{PostAuthAction, Route};
    use sqlx::PgPool;
    use ulid::Ulid;

    use super::UpstreamLogoutCookie;
    use crate::test_utils::{CookieHelper, RequestBuilderExt, TestState, setup};

    fn location(response: &axum::response::Response<String>) -> String {
        response
            .headers()
            .get(LOCATION)
            .expect("Location header")
            .to_str()
            .unwrap()
            .to_owned()
    }

    /// A matching `state` resumes the stashed post-auth action.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_logout_state_match(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Stash a logout cookie with a known state and a manage-account action
        let logout_cookie = UpstreamLogoutCookie::new(
            Ulid::nil(),
            "the-state".to_owned(),
            Some(PostAuthAction::manage_account(None)),
        );
        let cookie_jar = logout_cookie.save(state.cookie_jar());
        cookies.import(cookie_jar);

        let path = format!(
            "{}?state=the-state",
            mas_router::UpstreamOAuth2PostLogout.path()
        );
        let request = hyper::Request::get(&*path).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);

        assert!(response.status().is_redirection());
        // Manage-account redirects to the account management URL, not /login
        let location = location(&response);
        assert!(
            !location.ends_with("/login"),
            "expected to resume the post-auth action, got {location}"
        );
    }

    /// A mismatched `state` soft-fails to the login page.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_logout_state_mismatch(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let logout_cookie = UpstreamLogoutCookie::new(
            Ulid::nil(),
            "the-state".to_owned(),
            Some(PostAuthAction::manage_account(None)),
        );
        let cookie_jar = logout_cookie.save(state.cookie_jar());
        cookies.import(cookie_jar);

        let path = format!(
            "{}?state=wrong-state",
            mas_router::UpstreamOAuth2PostLogout.path()
        );
        let request = hyper::Request::get(&*path).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);

        assert!(response.status().is_redirection());
        assert!(location(&response).ends_with("/login"));
    }

    /// A missing cookie soft-fails to the login page.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_post_logout_no_cookie(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let path = format!(
            "{}?state=whatever",
            mas_router::UpstreamOAuth2PostLogout.path()
        );
        let request = hyper::Request::get(&*path).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);

        assert!(response.status().is_redirection());
        assert!(location(&response).ends_with("/login"));
    }
}
