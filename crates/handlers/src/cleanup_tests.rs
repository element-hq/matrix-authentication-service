// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Integration tests for session cleanup jobs.
//!
//! These tests verify that cleanup jobs correctly respect the session hierarchy
//! required for OIDC Backchannel Logout to function properly.
//!
//! Session hierarchy:
//! ```text
//! upstream_oauth_authorization_sessions (matched by sub/sid claims)
//!          │ user_session_id
//!          ▼
//!    user_sessions (browser sessions)
//!          │ user_session_id FK
//!     ┌────┴──────────────┐
//!     │                   │
//!     ▼                   ▼
//! compat_sessions    oauth2_sessions
//! ```

use chrono::Duration;
use hyper::{Request, StatusCode};
use mas_data_model::{
    BrowserSession, Clock as _, CompatSession, Device, UpstreamOAuthAuthorizationSession,
    UpstreamOAuthLink, UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
    UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
    UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod, User,
};
use mas_iana::jose::JsonWebSignatureAlg;
use mas_jose::jwt::{JsonWebSignatureHeader, Jwt};
use mas_storage::{
    RepositoryAccess,
    queue::{DeactivateUserJob, QueueJobRepositoryExt},
    upstream_oauth2::UpstreamOAuthProviderParams,
};
use oauth2_types::scope::{OPENID, Scope};
use sqlx::PgPool;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

/// Helper struct to hold all the entities created for testing the session
/// hierarchy.
struct TestSessionHierarchy {
    user: User,
    browser_session: BrowserSession,
    compat_session: Option<CompatSession>,
    oauth2_session: Option<mas_data_model::Session>,
    upstream_session: Option<UpstreamOAuthAuthorizationSession>,
    #[expect(dead_code)]
    upstream_link: Option<UpstreamOAuthLink>,
    provider: Option<UpstreamOAuthProvider>,
    #[expect(dead_code)]
    mock_server: MockServer,
}

const UPSTREAM_OAUTH_ISSUER: &str = "https://idp.example.com";
const UPSTREAM_OAUTH_CLIENT_ID: &str = "test-client";
const UPSTREAM_OAUTH_SESSION_ID: &str = "upstream-oauth-session-id";
const UPSTREAM_OAUTH_SUBJECT: &str = "upstream-oauth-sub";

/// Create the complete session hierarchy for testing.
///
/// This creates:
/// - A user
/// - A browser session
/// - Optionally a compat session linked to the browser session
/// - Optionally an OAuth 2.0 session linked to the browser session
/// - Optionally an upstream OAuth session linked to the browser session
async fn create_session_hierarchy(
    state: &TestState,
    with_compat: bool,
    with_oauth2: bool,
    with_upstream: bool,
) -> TestSessionHierarchy {
    let mut rng = state.rng();
    let mut repo = state.repository().await.unwrap();

    // Start a mock server to answer to JWKS requests for the backchannel logout
    // tests
    let mock_server = MockServer::start().await;

    let jwks = state.key_store.public_jwks();

    let mock_jwks = Mock::given(method("GET"))
        .and(path("jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks));
    mock_server.register(mock_jwks).await;

    // Create user
    let user = repo
        .user()
        .add(&mut rng, &state.clock, "testuser".to_owned())
        .await
        .unwrap();

    // Create browser session
    let browser_session = repo
        .browser_session()
        .add(&mut rng, &state.clock, &user, None)
        .await
        .unwrap();

    // Create compat session if requested
    let compat_session = if with_compat {
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(
                &mut rng,
                &state.clock,
                &user,
                device,
                Some(&browser_session),
                false,
                None,
            )
            .await
            .unwrap();
        Some(session)
    } else {
        None
    };

    // Create OAuth2 session if requested
    let oauth2_session = if with_oauth2 {
        // First create an OAuth2 client
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &state.clock,
                vec!["https://example.com/callback".parse().unwrap()],
                None,
                None,
                None,
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let session = repo
            .oauth2_session()
            .add_from_browser_session(
                &mut rng,
                &state.clock,
                &client,
                &browser_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        Some(session)
    } else {
        None
    };

    // Create upstream OAuth session if requested
    let (provider, upstream_link, upstream_session) = if with_upstream {
        let params = UpstreamOAuthProviderParams {
            issuer: Some(UPSTREAM_OAUTH_ISSUER.to_owned()),
            human_name: Some("Test IdP".to_owned()),
            brand_name: None,
            scope: Scope::from_iter([OPENID]),
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic,
            token_endpoint_signing_alg: None,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            fetch_userinfo: false,
            userinfo_signed_response_alg: None,
            client_id: UPSTREAM_OAUTH_CLIENT_ID.to_owned(),
            encrypted_client_secret: None,
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            // Point to the mock server to have it use a JWKS we can use for signing
            jwks_uri_override: Some(format!("{}/jwks.json", mock_server.uri()).parse().unwrap()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Disabled,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            response_mode: None,
            additional_authorization_parameters: vec![],
            forward_login_hint: false,
            ui_order: 0,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::LogoutAll,
        };

        let provider = repo
            .upstream_oauth_provider()
            .add(&mut rng, &state.clock, params)
            .await
            .unwrap();

        // Create a link
        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                UPSTREAM_OAUTH_SUBJECT.to_owned(),
                Some("test@idp.example.com".to_owned()),
            )
            .await
            .unwrap();

        // Associate link to user
        repo.upstream_oauth_link()
            .associate_to_user(&link, &user)
            .await
            .unwrap();

        // Create an upstream session
        let session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "state123".to_owned(),
                Some("verifier123".to_owned()),
                Some("nonce123".to_owned()),
            )
            .await
            .unwrap();

        // Complete the session with the link and ID token claims (including sub and
        // sid)
        let id_token_claims = serde_json::json!({
            "sub": UPSTREAM_OAUTH_SUBJECT,
            "sid": UPSTREAM_OAUTH_SESSION_ID,
        });
        let session = repo
            .upstream_oauth_session()
            .complete_with_link(
                &state.clock,
                session,
                &link,
                Some("fake-id-token".to_owned()),
                Some(id_token_claims),
                None,
                None,
            )
            .await
            .unwrap();

        // Consume the session and link it to the browser session
        let session = repo
            .upstream_oauth_session()
            .consume(&state.clock, session, &browser_session)
            .await
            .unwrap();

        (Some(provider), Some(link), Some(session))
    } else {
        (None, None, None)
    };

    repo.save().await.unwrap();

    TestSessionHierarchy {
        user,
        browser_session,
        compat_session,
        oauth2_session,
        upstream_session,
        upstream_link,
        provider,
        mock_server,
    }
}

/// Test that sessions finished less than 30 days ago are NOT deleted.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_cleanup_sessions_within_retention_preserved(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Create a full hierarchy with all session types
    let hierarchy = create_session_hierarchy(&state, true, true, false).await;

    // Finish all sessions
    let mut repo = state.repository().await.unwrap();
    let browser_session = repo
        .browser_session()
        .finish(&state.clock, hierarchy.browser_session)
        .await
        .unwrap();
    let compat_session = repo
        .compat_session()
        .finish(&state.clock, hierarchy.compat_session.unwrap())
        .await
        .unwrap();
    let oauth2_session = repo
        .oauth2_session()
        .finish(&state.clock, hierarchy.oauth2_session.unwrap())
        .await
        .unwrap();
    repo.save().await.unwrap();

    // Wait one day and run the cleanup jobs a few times
    state.clock.advance(Duration::try_days(1).unwrap());
    state.run_jobs_in_queue().await;
    for _ in 0..5 {
        state.clock.advance(Duration::try_hours(1).unwrap());
        state.run_jobs_in_queue().await;
    }

    // Verify all sessions still exist
    let mut repo = state.repository().await.unwrap();
    assert!(
        repo.browser_session()
            .lookup(browser_session.id)
            .await
            .unwrap()
            .is_some(),
        "Browser session should still exist"
    );
    assert!(
        repo.compat_session()
            .lookup(compat_session.id)
            .await
            .unwrap()
            .is_some(),
        "Compat session should still exist"
    );
    assert!(
        repo.oauth2_session()
            .lookup(oauth2_session.id)
            .await
            .unwrap()
            .is_some(),
        "OAuth2 session should still exist"
    );
}

/// Test that deactivated users eventually get all their sessions cleaned up
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_cleanup_deactivated_users(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    let mut rng = state.rng();

    // Create a hierarchy with all session types
    let hierarchy = create_session_hierarchy(&state, true, true, true).await;

    // Deactivate the user
    let mut repo = state.repository().await.unwrap();
    let user = repo
        .user()
        .lookup(hierarchy.user.id)
        .await
        .unwrap()
        .unwrap();
    let user = repo.user().deactivate(&state.clock, user).await.unwrap();
    repo.queue_job()
        .schedule_job(&mut rng, &state.clock, DeactivateUserJob::new(&user, false))
        .await
        .unwrap();
    repo.save().await.unwrap();

    state.run_jobs_in_queue().await;

    // Verify all sessions are finished
    let mut repo = state.repository().await.unwrap();
    assert!(
        repo.compat_session()
            .lookup(hierarchy.compat_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .unwrap()
            .is_finished(),
        "Compat session should be finished"
    );
    assert!(
        repo.oauth2_session()
            .lookup(hierarchy.oauth2_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .unwrap()
            .is_finished(),
        "OAuth2 session should be finished"
    );
    assert!(
        repo.browser_session()
            .lookup(hierarchy.browser_session.id)
            .await
            .unwrap()
            .unwrap()
            .finished_at
            .is_some(),
        "Browser session should be there"
    );
    assert!(
        repo.upstream_oauth_session()
            .lookup(hierarchy.upstream_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .is_some(),
        "Upstream OAuth session should be there"
    );

    // Wait 31 days and run the cleanup jobs a few times
    state.clock.advance(Duration::try_days(31).unwrap());
    state.run_jobs_in_queue().await;
    for _ in 0..5 {
        state.clock.advance(Duration::try_hours(1).unwrap());
        state.run_jobs_in_queue().await;
    }

    // Verify all sessions are deleted
    let mut repo = state.repository().await.unwrap();
    assert!(
        repo.compat_session()
            .lookup(hierarchy.compat_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .is_none(),
        "Compat session should be deleted"
    );
    assert!(
        repo.oauth2_session()
            .lookup(hierarchy.oauth2_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .is_none(),
        "OAuth2 session should be deleted"
    );
    assert!(
        repo.browser_session()
            .lookup(hierarchy.browser_session.id)
            .await
            .unwrap()
            .is_none(),
        "Browser session should be deleted"
    );
    assert!(
        repo.upstream_oauth_session()
            .lookup(hierarchy.upstream_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .is_none(),
        "Upstream OAuth session should be deleted"
    );
}

/// Test that sessions finished more than 30 days ago ARE deleted.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_cleanup_sessions_after_retention_deleted(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Create hierarchy with compat and oauth2 sessions
    let hierarchy = create_session_hierarchy(&state, true, true, false).await;

    // Finish all sessions
    let mut repo = state.repository().await.unwrap();
    let browser_session = repo
        .browser_session()
        .finish(&state.clock, hierarchy.browser_session)
        .await
        .unwrap();
    let compat_session = repo
        .compat_session()
        .finish(&state.clock, hierarchy.compat_session.unwrap())
        .await
        .unwrap();
    let oauth2_session = repo
        .oauth2_session()
        .finish(&state.clock, hierarchy.oauth2_session.unwrap())
        .await
        .unwrap();
    repo.save().await.unwrap();

    // Wait 31 days and run the cleanup jobs a few times
    state.clock.advance(Duration::try_days(31).unwrap());
    state.run_jobs_in_queue().await;
    for _ in 0..5 {
        state.clock.advance(Duration::try_hours(1).unwrap());
        state.run_jobs_in_queue().await;
    }

    // Verify all sessions are deleted
    let mut repo = state.repository().await.unwrap();
    assert!(
        repo.compat_session()
            .lookup(compat_session.id)
            .await
            .unwrap()
            .is_none(),
        "Compat session should be deleted"
    );
    assert!(
        repo.oauth2_session()
            .lookup(oauth2_session.id)
            .await
            .unwrap()
            .is_none(),
        "OAuth2 session should be deleted"
    );
    // Browser session should also be deleted since children are gone
    assert!(
        repo.browser_session()
            .lookup(browser_session.id)
            .await
            .unwrap()
            .is_none(),
        "Browser session should be deleted after children are gone"
    );
}

/// Test that user sessions with remaining child sessions are NOT deleted.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_cleanup_user_session_blocked_by_child_sessions(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Create hierarchy with compat session only
    let hierarchy = create_session_hierarchy(&state, true, false, false).await;

    // Finish only the browser session (not the compat session)
    let mut repo = state.repository().await.unwrap();
    let browser_session = repo
        .browser_session()
        .finish(&state.clock, hierarchy.browser_session)
        .await
        .unwrap();
    repo.save().await.unwrap();

    let compat_session_id = hierarchy.compat_session.as_ref().unwrap().id;

    // Wait 31 days and run the cleanup jobs a few times
    state.clock.advance(Duration::try_days(31).unwrap());
    state.run_jobs_in_queue().await;
    for _ in 0..5 {
        state.clock.advance(Duration::try_hours(1).unwrap());
        state.run_jobs_in_queue().await;
    }

    // Verify browser session still exists because compat session is still active
    let mut repo = state.repository().await.unwrap();
    assert!(
        repo.browser_session()
            .lookup(browser_session.id)
            .await
            .unwrap()
            .is_some(),
        "Browser session should NOT be deleted because it has an active child session"
    );
    assert!(
        repo.compat_session()
            .lookup(compat_session_id)
            .await
            .unwrap()
            .is_some(),
        "Compat session should still exist (not finished)"
    );
}

/// Test that backchannel logout can find sessions before cleanup.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_backchannel_logout_works_before_cleanup(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Create hierarchy with upstream session
    let hierarchy = create_session_hierarchy(&state, true, true, true).await;

    let provider = hierarchy.provider.as_ref().unwrap();

    // The edge case we're trying to make works, is that if the browser session
    // is finished for 30 days but *not* the child sessions, that browser
    // session and the upstream sessions stay there so that backchannel logout
    // still works
    let mut repo = state.repository().await.unwrap();
    let browser_session = repo
        .browser_session()
        .lookup(hierarchy.browser_session.id)
        .await
        .unwrap()
        .unwrap();
    repo.browser_session()
        .finish(&state.clock, browser_session)
        .await
        .unwrap();
    repo.save().await.unwrap();

    // Now wait 31 days and run the cleanup jobs a few times
    state.clock.advance(Duration::try_days(31).unwrap());
    state.run_jobs_in_queue().await;
    for _ in 0..5 {
        state.clock.advance(Duration::try_hours(1).unwrap());
        state.run_jobs_in_queue().await;
    }

    // Now let's craft a backchannel logout request
    let ts = state.clock.now().timestamp();
    let payload = serde_json::json!({
        "iss": UPSTREAM_OAUTH_ISSUER,
        "aud": UPSTREAM_OAUTH_CLIENT_ID,
        "sub": UPSTREAM_OAUTH_SUBJECT,
        "sid": UPSTREAM_OAUTH_SESSION_ID,
        "jti": "iswearthisisrandom",
        "iat": ts,
        "exp": ts + 300,
        "events": {
            "http://schemas.openid.net/event/backchannel-logout": {}
        }
    });

    let key = state
        .key_store
        .signing_key_for_algorithm(&JsonWebSignatureAlg::Rs256)
        .unwrap();
    let signer = key
        .params()
        .signing_key_for_alg(&JsonWebSignatureAlg::Rs256)
        .unwrap();
    let signed = Jwt::sign(
        JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256),
        payload,
        &signer,
    )
    .unwrap();

    let request = Request::post(format!("/upstream/backchannel-logout/{}", provider.id)).form(
        serde_json::json!({
            "logout_token": signed.as_str(),
        }),
    );

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);

    // The session should still exist, but are finished
    let mut repo = state.repository().await.unwrap();
    assert!(
        !repo
            .browser_session()
            .lookup(hierarchy.browser_session.id)
            .await
            .unwrap()
            .unwrap()
            .active(),
        "Inactive browser session should not be cleaned up"
    );
    assert!(
        repo.compat_session()
            .lookup(hierarchy.compat_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .unwrap()
            .is_finished(),
        "Active compat session should not be cleaned up"
    );
    assert!(
        repo.oauth2_session()
            .lookup(hierarchy.oauth2_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .unwrap()
            .is_finished(),
        "Active OAuth2 session should not be cleaned up"
    );

    // Wait again, then the sessions should be completely deleted
    state.clock.advance(Duration::try_days(31).unwrap());
    state.run_jobs_in_queue().await;
    for _ in 0..5 {
        state.clock.advance(Duration::try_hours(1).unwrap());
        state.run_jobs_in_queue().await;
    }

    let mut repo = state.repository().await.unwrap();
    assert!(
        repo.browser_session()
            .lookup(hierarchy.browser_session.id)
            .await
            .unwrap()
            .is_none(),
        "Browser session should be deleted"
    );
    assert!(
        repo.compat_session()
            .lookup(hierarchy.compat_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .is_none(),
        "Compat session should be deleted"
    );
    assert!(
        repo.oauth2_session()
            .lookup(hierarchy.oauth2_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .is_none(),
        "OAuth2 session should be deleted"
    );
    assert!(
        repo.upstream_oauth_session()
            .lookup(hierarchy.upstream_session.as_ref().unwrap().id)
            .await
            .unwrap()
            .is_none(),
        "Upstream OAuth session should be deleted"
    );
}

/// Test that active sessions are not cleaned up even after retention period.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_active_sessions_not_cleaned_up(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Create hierarchy without finishing any sessions
    let hierarchy = create_session_hierarchy(&state, true, true, false).await;

    let browser_session_id = hierarchy.browser_session.id;
    let compat_session_id = hierarchy.compat_session.as_ref().unwrap().id;
    let oauth2_session_id = hierarchy.oauth2_session.as_ref().unwrap().id;

    // Wait 31 days and run the cleanup jobs a few times
    state.clock.advance(Duration::try_days(31).unwrap());
    state.run_jobs_in_queue().await;
    for _ in 0..5 {
        state.clock.advance(Duration::try_hours(1).unwrap());
        state.run_jobs_in_queue().await;
    }

    // All sessions should still exist because they're active
    let mut repo = state.repository().await.unwrap();
    assert!(
        repo.browser_session()
            .lookup(browser_session_id)
            .await
            .unwrap()
            .is_some(),
        "Active browser session should not be cleaned up"
    );
    assert!(
        repo.compat_session()
            .lookup(compat_session_id)
            .await
            .unwrap()
            .is_some(),
        "Active compat session should not be cleaned up"
    );
    assert!(
        repo.oauth2_session()
            .lookup(oauth2_session_id)
            .await
            .unwrap()
            .is_some(),
        "Active OAuth2 session should not be cleaned up"
    );
}
