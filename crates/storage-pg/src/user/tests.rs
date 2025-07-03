// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use chrono::Duration;
use mas_iana::jose::JsonWebSignatureAlg;
use mas_storage::{
    Clock, Pagination, RepositoryAccess,
    clock::MockClock,
    upstream_oauth2::UpstreamOAuthProviderParams,
    user::{
        BrowserSessionFilter, BrowserSessionRepository, UserEmailFilter, UserEmailRepository,
        UserFilter, UserPasswordRepository, UserRepository,
    },
};
use oauth2_types::scope::{OPENID, Scope};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sqlx::PgPool;

use crate::PgRepository;

/// Test the user repository, by adding and looking up a user
#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_repo(pool: PgPool) {
    const USERNAME: &str = "john";

    let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let all = UserFilter::new();
    let admin = all.can_request_admin_only();
    let non_admin = all.cannot_request_admin_only();
    let active = all.active_only();
    let locked = all.locked_only();
    let deactivated = all.deactivated_only();

    // Initially, the user shouldn't exist
    assert!(!repo.user().exists(USERNAME).await.unwrap());
    assert!(
        repo.user()
            .find_by_username(USERNAME)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(repo.user().count(all).await.unwrap(), 0);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(active).await.unwrap(), 0);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Adding the user should work
    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    // And now it should exist
    assert!(repo.user().exists(USERNAME).await.unwrap());
    assert!(
        repo.user()
            .find_by_username(USERNAME)
            .await
            .unwrap()
            .is_some()
    );
    assert!(repo.user().lookup(user.id).await.unwrap().is_some());

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(active).await.unwrap(), 1);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Adding a second time should give a conflict
    // It should not poison the transaction though
    assert!(
        repo.user()
            .add(&mut rng, &clock, USERNAME.to_owned())
            .await
            .is_err()
    );

    // Try locking a user
    assert!(user.is_valid());
    let user = repo.user().lock(&clock, user).await.unwrap();
    assert!(!user.is_valid());

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(active).await.unwrap(), 0);
    assert_eq!(repo.user().count(locked).await.unwrap(), 1);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(!user.is_valid());

    // Locking a second time should not fail
    let user = repo.user().lock(&clock, user).await.unwrap();
    assert!(!user.is_valid());

    // Try unlocking a user
    let user = repo.user().unlock(user).await.unwrap();
    assert!(user.is_valid());

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(user.is_valid());

    // Unlocking a second time should not fail
    let user = repo.user().unlock(user).await.unwrap();
    assert!(user.is_valid());

    // Set the can_request_admin flag
    let user = repo.user().set_can_request_admin(user, true).await.unwrap();
    assert!(user.can_request_admin);

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(active).await.unwrap(), 1);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(user.can_request_admin);

    // Unset the can_request_admin flag
    let user = repo
        .user()
        .set_can_request_admin(user, false)
        .await
        .unwrap();
    assert!(!user.can_request_admin);

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(!user.can_request_admin);

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(active).await.unwrap(), 1);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Deactivating the user should work
    let user = repo.user().deactivate(&clock, user).await.unwrap();
    assert!(user.deactivated_at.is_some());

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(user.deactivated_at.is_some());

    // Deactivating a second time should not fail
    let user = repo.user().deactivate(&clock, user).await.unwrap();
    assert!(user.deactivated_at.is_some());

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(active).await.unwrap(), 0);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 1);

    // Check the list method
    let list = repo.user().list(all, Pagination::first(10)).await.unwrap();
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].id, user.id);

    let list = repo
        .user()
        .list(admin, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 0);

    let list = repo
        .user()
        .list(non_admin, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].id, user.id);

    let list = repo
        .user()
        .list(active, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 0);

    let list = repo
        .user()
        .list(locked, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 0);

    let list = repo
        .user()
        .list(deactivated, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].id, user.id);

    repo.save().await.unwrap();
}

/// Test [`UserRepository::find_by_username`] with different casings.
#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_repo_find_by_username(pool: PgPool) {
    let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let alice = repo
        .user()
        .add(&mut rng, &clock, "Alice".to_owned())
        .await
        .unwrap();
    let bob1 = repo
        .user()
        .add(&mut rng, &clock, "Bob".to_owned())
        .await
        .unwrap();
    let bob2 = repo
        .user()
        .add(&mut rng, &clock, "BOB".to_owned())
        .await
        .unwrap();

    // This is fine, we can do a case-insensitive search
    assert_eq!(
        repo.user().find_by_username("alice").await.unwrap(),
        Some(alice)
    );

    // In case there are multiple users with the same username, we should return the
    // one that matches the exact casing
    assert_eq!(
        repo.user().find_by_username("Bob").await.unwrap(),
        Some(bob1)
    );
    assert_eq!(
        repo.user().find_by_username("BOB").await.unwrap(),
        Some(bob2)
    );

    // If none match, we should return None
    assert!(repo.user().find_by_username("bob").await.unwrap().is_none());
}

/// Test the user email repository, by trying out most of its methods
#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_email_repo(pool: PgPool) {
    const USERNAME: &str = "john";
    const EMAIL: &str = "john@example.com";

    let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    // The user email should not exist yet
    assert!(
        repo.user_email()
            .find(&user, EMAIL)
            .await
            .unwrap()
            .is_none()
    );

    let all = UserEmailFilter::new().for_user(&user);

    // Check the counts
    assert_eq!(repo.user_email().count(all).await.unwrap(), 0);

    let user_email = repo
        .user_email()
        .add(&mut rng, &clock, &user, EMAIL.to_owned())
        .await
        .unwrap();

    assert_eq!(user_email.user_id, user.id);
    assert_eq!(user_email.email, EMAIL);

    // Check the counts
    assert_eq!(repo.user_email().count(all).await.unwrap(), 1);

    assert!(
        repo.user_email()
            .find(&user, EMAIL)
            .await
            .unwrap()
            .is_some()
    );

    let user_email = repo
        .user_email()
        .lookup(user_email.id)
        .await
        .unwrap()
        .expect("user email was not found");

    assert_eq!(user_email.user_id, user.id);
    assert_eq!(user_email.email, EMAIL);

    // Listing the user emails should work
    let emails = repo
        .user_email()
        .list(all, Pagination::first(10))
        .await
        .unwrap();
    assert!(!emails.has_next_page);
    assert_eq!(emails.edges.len(), 1);
    assert_eq!(emails.edges[0], user_email);

    // Listing emails from the email address should work
    let emails = repo
        .user_email()
        .list(all.for_email(EMAIL), Pagination::first(10))
        .await
        .unwrap();
    assert!(!emails.has_next_page);
    assert_eq!(emails.edges.len(), 1);
    assert_eq!(emails.edges[0], user_email);

    // Filtering on another email should not return anything
    let emails = repo
        .user_email()
        .list(all.for_email("hello@example.com"), Pagination::first(10))
        .await
        .unwrap();
    assert!(!emails.has_next_page);
    assert!(emails.edges.is_empty());

    // Counting also works with the email filter
    assert_eq!(
        repo.user_email().count(all.for_email(EMAIL)).await.unwrap(),
        1
    );
    assert_eq!(
        repo.user_email()
            .count(all.for_email("hello@example.com"))
            .await
            .unwrap(),
        0
    );

    // Deleting the user email should work
    repo.user_email().remove(user_email).await.unwrap();
    assert_eq!(repo.user_email().count(all).await.unwrap(), 0);

    // Add a few emails
    for i in 0..5 {
        let email = format!("email{i}@example.com");
        repo.user_email()
            .add(&mut rng, &clock, &user, email)
            .await
            .unwrap();
    }
    assert_eq!(repo.user_email().count(all).await.unwrap(), 5);

    // Try removing all the emails
    let affected = repo.user_email().remove_bulk(all).await.unwrap();
    assert_eq!(affected, 5);
    assert_eq!(repo.user_email().count(all).await.unwrap(), 0);

    repo.save().await.unwrap();
}

/// Test the authentication codes methods in the user email repository
#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_email_repo_authentications(pool: PgPool) {
    let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    // Create a user and a user session so that we can create an authentication
    let user = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();

    let browser_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, None)
        .await
        .unwrap();

    // Create an authentication session
    let authentication = repo
        .user_email()
        .add_authentication_for_session(
            &mut rng,
            &clock,
            "alice@example.com".to_owned(),
            &browser_session,
        )
        .await
        .unwrap();

    assert_eq!(authentication.email, "alice@example.com");
    assert_eq!(authentication.user_session_id, Some(browser_session.id));
    assert_eq!(authentication.created_at, clock.now());
    assert_eq!(authentication.completed_at, None);

    // Check that we can find the authentication by its ID
    let lookup = repo
        .user_email()
        .lookup_authentication(authentication.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lookup.id, authentication.id);
    assert_eq!(lookup.email, "alice@example.com");
    assert_eq!(lookup.user_session_id, Some(browser_session.id));
    assert_eq!(lookup.created_at, clock.now());
    assert_eq!(lookup.completed_at, None);

    // Add a code to the session
    let code = repo
        .user_email()
        .add_authentication_code(
            &mut rng,
            &clock,
            Duration::minutes(5),
            &authentication,
            "123456".to_owned(),
        )
        .await
        .unwrap();

    assert_eq!(code.code, "123456");
    assert_eq!(code.created_at, clock.now());
    assert_eq!(code.expires_at, clock.now() + Duration::minutes(5));

    // Check that we can find the code by its ID
    let id = code.id;
    let lookup = repo
        .user_email()
        .find_authentication_code(&authentication, "123456")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(lookup.id, id);
    assert_eq!(lookup.code, "123456");
    assert_eq!(lookup.created_at, clock.now());
    assert_eq!(lookup.expires_at, clock.now() + Duration::minutes(5));

    // Complete the authentication
    let authentication = repo
        .user_email()
        .complete_authentication(&clock, authentication, &code)
        .await
        .unwrap();

    assert_eq!(authentication.id, authentication.id);
    assert_eq!(authentication.email, "alice@example.com");
    assert_eq!(authentication.user_session_id, Some(browser_session.id));
    assert_eq!(authentication.created_at, clock.now());
    assert_eq!(authentication.completed_at, Some(clock.now()));

    // Check that we can find the completed authentication by its ID
    let lookup = repo
        .user_email()
        .lookup_authentication(authentication.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lookup.id, authentication.id);
    assert_eq!(lookup.email, "alice@example.com");
    assert_eq!(lookup.user_session_id, Some(browser_session.id));
    assert_eq!(lookup.created_at, clock.now());
    assert_eq!(lookup.completed_at, Some(clock.now()));

    // Completing a second time should fail
    let res = repo
        .user_email()
        .complete_authentication(&clock, authentication, &code)
        .await;
    assert!(res.is_err());
}

/// Test the user password repository implementation.
#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_password_repo(pool: PgPool) {
    const USERNAME: &str = "john";
    const FIRST_PASSWORD_HASH: &str = "doesntmatter";
    const SECOND_PASSWORD_HASH: &str = "alsodoesntmatter";

    let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    // User should have no active password
    assert!(repo.user_password().active(&user).await.unwrap().is_none());

    // Insert a first password
    let first_password = repo
        .user_password()
        .add(
            &mut rng,
            &clock,
            &user,
            1,
            FIRST_PASSWORD_HASH.to_owned(),
            None,
        )
        .await
        .unwrap();

    // User should now have an active password
    let first_password_lookup = repo
        .user_password()
        .active(&user)
        .await
        .unwrap()
        .expect("user should have an active password");

    assert_eq!(first_password.id, first_password_lookup.id);
    assert_eq!(first_password_lookup.hashed_password, FIRST_PASSWORD_HASH);
    assert_eq!(first_password_lookup.version, 1);
    assert_eq!(first_password_lookup.upgraded_from_id, None);

    // Getting the last inserted password is based on the clock, so we need to
    // advance it
    clock.advance(Duration::microseconds(10 * 1000 * 1000));

    let second_password = repo
        .user_password()
        .add(
            &mut rng,
            &clock,
            &user,
            2,
            SECOND_PASSWORD_HASH.to_owned(),
            Some(&first_password),
        )
        .await
        .unwrap();

    // User should now have an active password
    let second_password_lookup = repo
        .user_password()
        .active(&user)
        .await
        .unwrap()
        .expect("user should have an active password");

    assert_eq!(second_password.id, second_password_lookup.id);
    assert_eq!(second_password_lookup.hashed_password, SECOND_PASSWORD_HASH);
    assert_eq!(second_password_lookup.version, 2);
    assert_eq!(
        second_password_lookup.upgraded_from_id,
        Some(first_password.id)
    );

    repo.save().await.unwrap();
}

#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_session(pool: PgPool) {
    let mut repo = PgRepository::from_pool(&pool).await.unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let alice = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();

    let bob = repo
        .user()
        .add(&mut rng, &clock, "bob".to_owned())
        .await
        .unwrap();

    let all = BrowserSessionFilter::default();
    let active = all.active_only();
    let finished = all.finished_only();

    assert_eq!(repo.browser_session().count(all).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 0);

    let session = repo
        .browser_session()
        .add(&mut rng, &clock, &alice, None)
        .await
        .unwrap();
    assert_eq!(session.user.id, alice.id);
    assert!(session.finished_at.is_none());

    assert_eq!(repo.browser_session().count(all).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 0);

    // The session should be in the list of active sessions
    let session_list = repo
        .browser_session()
        .list(active, Pagination::first(10))
        .await
        .unwrap();
    assert!(!session_list.has_next_page);
    assert_eq!(session_list.edges.len(), 1);
    assert_eq!(session_list.edges[0], session);

    let session_lookup = repo
        .browser_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("user session not found");

    assert_eq!(session_lookup.id, session.id);
    assert_eq!(session_lookup.user.id, alice.id);
    assert!(session_lookup.finished_at.is_none());

    // Finish the session
    repo.browser_session()
        .finish(&clock, session_lookup)
        .await
        .unwrap();

    // The active session counter should be 0, and the finished one should be 1
    assert_eq!(repo.browser_session().count(all).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 1);

    // The session should not be in the list of active sessions anymore
    let session_list = repo
        .browser_session()
        .list(active, Pagination::first(10))
        .await
        .unwrap();
    assert!(!session_list.has_next_page);
    assert!(session_list.edges.is_empty());

    // Reload the session
    let session_lookup = repo
        .browser_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("user session not found");

    assert_eq!(session_lookup.id, session.id);
    assert_eq!(session_lookup.user.id, alice.id);
    // This time the session is finished
    assert!(session_lookup.finished_at.is_some());

    // Create a bunch of other sessions
    for _ in 0..5 {
        for user in &[&alice, &bob] {
            repo.browser_session()
                .add(&mut rng, &clock, user, None)
                .await
                .unwrap();
        }
    }

    let all_alice = BrowserSessionFilter::new().for_user(&alice);
    let active_alice = BrowserSessionFilter::new().for_user(&alice).active_only();
    let all_bob = BrowserSessionFilter::new().for_user(&bob);
    let active_bob = BrowserSessionFilter::new().for_user(&bob).active_only();
    assert_eq!(repo.browser_session().count(all).await.unwrap(), 11);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 10);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(all_alice).await.unwrap(), 6);
    assert_eq!(repo.browser_session().count(active_alice).await.unwrap(), 5);
    assert_eq!(repo.browser_session().count(all_bob).await.unwrap(), 5);
    assert_eq!(repo.browser_session().count(active_bob).await.unwrap(), 5);

    // Finish all the sessions for alice
    let affected = repo
        .browser_session()
        .finish_bulk(&clock, active_alice)
        .await
        .unwrap();
    assert_eq!(affected, 5);
    assert_eq!(repo.browser_session().count(all_alice).await.unwrap(), 6);
    assert_eq!(repo.browser_session().count(active_alice).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 6);

    // Finish all the sessions for bob
    let affected = repo
        .browser_session()
        .finish_bulk(&clock, active_bob)
        .await
        .unwrap();
    assert_eq!(affected, 5);
    assert_eq!(repo.browser_session().count(all_bob).await.unwrap(), 5);
    assert_eq!(repo.browser_session().count(active_bob).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 11);

    // Checking the 'authenticaated by upstream sessions' filter
    // We need a provider
    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &clock,
            UpstreamOAuthProviderParams {
                issuer: None,
                human_name: None,
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method:
                    mas_data_model::UpstreamOAuthProviderTokenAuthMethod::None,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                client_id: "client".to_owned(),
                encrypted_client_secret: None,
                claims_imports: mas_data_model::UpstreamOAuthProviderClaimsImports::default(),
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                userinfo_endpoint_override: None,
                jwks_uri_override: None,
                discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Disabled,
                pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Disabled,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                ui_order: 0,
                on_backchannel_logout:
                    mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            },
        )
        .await
        .unwrap();

    // Start a authorization session
    let upstream_oauth_session = repo
        .upstream_oauth_session()
        .add(&mut rng, &clock, &provider, "state".to_owned(), None, None)
        .await
        .unwrap();

    // Start a browser session
    let session = repo
        .browser_session()
        .add(&mut rng, &clock, &alice, None)
        .await
        .unwrap();

    // Make the session from alice authenticated by this session
    repo.browser_session()
        .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_oauth_session)
        .await
        .unwrap();

    let session_list = vec![upstream_oauth_session];
    let filter = BrowserSessionFilter::new().authenticated_by_upstream_sessions_only(&session_list);

    // Now try to look it up
    let page = repo
        .browser_session()
        .list(filter, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(page.edges.len(), 1);
    assert_eq!(page.edges[0].id, session.id);

    // Try counting
    assert_eq!(repo.browser_session().count(filter).await.unwrap(), 1);

    // Try finishing the session
    let affected = repo
        .browser_session()
        .finish_bulk(&clock, filter)
        .await
        .unwrap();
    assert_eq!(affected, 1);

    // Lookup the session by its ID
    let lookup = repo
        .browser_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("session to be found in the database");
    // It should be finished
    assert!(lookup.finished_at.is_some());
}

#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_terms(pool: PgPool) {
    let mut repo = PgRepository::from_pool(&pool).await.unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, "john".to_owned())
        .await
        .unwrap();

    // Accepting the terms should work
    repo.user_terms()
        .accept_terms(
            &mut rng,
            &clock,
            &user,
            "https://example.com/terms".parse().unwrap(),
        )
        .await
        .unwrap();

    // Accepting a second time should also work
    repo.user_terms()
        .accept_terms(
            &mut rng,
            &clock,
            &user,
            "https://example.com/terms".parse().unwrap(),
        )
        .await
        .unwrap();

    // Accepting a different terms should also work
    repo.user_terms()
        .accept_terms(
            &mut rng,
            &clock,
            &user,
            "https://example.com/terms?v=2".parse().unwrap(),
        )
        .await
        .unwrap();

    let mut conn = repo.into_inner();

    // We should have two rows, as the first terms was deduped
    let res: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_terms")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(res, 2);
}
