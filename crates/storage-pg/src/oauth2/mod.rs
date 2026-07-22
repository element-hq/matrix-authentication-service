// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! A module containing the PostgreSQL implementations of the OAuth2-related
//! repositories

mod access_token;
mod authorization_grant;
mod client;
mod device_code_grant;
mod refresh_token;
mod session;

pub use self::{
    access_token::PgOAuth2AccessTokenRepository,
    authorization_grant::PgOAuth2AuthorizationGrantRepository, client::PgOAuth2ClientRepository,
    device_code_grant::PgOAuth2DeviceCodeGrantRepository,
    refresh_token::PgOAuth2RefreshTokenRepository, session::PgOAuth2SessionRepository,
};

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_data_model::{AuthorizationCode, Clock, UlidExt as _, clock::MockClock};
    use mas_iana::oauth::OAuthClientAuthenticationMethod;
    use mas_storage::{
        Pagination,
        oauth2::{
            OAuth2ClientFilter, OAuth2DeviceCodeGrantParams, OAuth2SessionFilter,
            OAuth2SessionRepository,
        },
    };
    use oauth2_types::{
        requests::{GrantType, ResponseMode},
        scope::{EMAIL, OPENID, PROFILE, Scope},
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_repositories(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Lookup a non-existing client
        let client = repo.oauth2_client().lookup(Ulid::nil()).await.unwrap();
        assert_eq!(client, None);

        // Find a non-existing client by client id
        let client = repo
            .oauth2_client()
            .find_by_client_id("some-client-id")
            .await
            .unwrap();
        assert_eq!(client, None);

        // Create a client
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("Test client".to_owned()),
                Some("https://example.com/logo.png".parse().unwrap()),
                Some("https://example.com/".parse().unwrap()),
                Some("https://example.com/policy".parse().unwrap()),
                Some("https://example.com/tos".parse().unwrap()),
                Some("https://example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        // Lookup the same client by id
        let client_lookup = repo
            .oauth2_client()
            .lookup(client.id)
            .await
            .unwrap()
            .expect("client not found");
        assert_eq!(client, client_lookup);

        // Find the same client by client id
        let client_lookup = repo
            .oauth2_client()
            .find_by_client_id(&client.client_id)
            .await
            .unwrap()
            .expect("client not found");
        assert_eq!(client, client_lookup);

        // Lookup a non-existing grant
        let grant = repo
            .oauth2_authorization_grant()
            .lookup(Ulid::nil())
            .await
            .unwrap();
        assert_eq!(grant, None);

        // Find a non-existing grant by code
        let grant = repo
            .oauth2_authorization_grant()
            .find_by_code("code")
            .await
            .unwrap();
        assert_eq!(grant, None);

        // Create an authorization grant
        let raw_parameters = std::collections::BTreeMap::from([
            ("client_id".to_owned(), "client".to_owned()),
            ("foo".to_owned(), "bar".to_owned()),
        ]);
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut rng,
                &clock,
                &client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: "code".to_owned(),
                    pkce: None,
                }),
                Some("state".to_owned()),
                Some("nonce".to_owned()),
                ResponseMode::Query,
                true,
                None,
                None,
                raw_parameters.clone(),
            )
            .await
            .unwrap();
        assert!(grant.is_pending());
        assert_eq!(grant.raw_parameters, raw_parameters);

        // Lookup the same grant by id
        let grant_lookup = repo
            .oauth2_authorization_grant()
            .lookup(grant.id)
            .await
            .unwrap()
            .expect("grant not found");
        assert_eq!(grant, grant_lookup);

        // Find the same grant by code
        let grant_lookup = repo
            .oauth2_authorization_grant()
            .find_by_code("code")
            .await
            .unwrap()
            .expect("grant not found");
        assert_eq!(grant, grant_lookup);

        // Create a user and a start a user session
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();
        let user_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();

        // mark the grant as fulfilled with the browser session
        let grant = repo
            .oauth2_authorization_grant()
            .fulfill(&clock, &user_session, grant)
            .await
            .unwrap();
        assert!(grant.is_fulfilled());

        // Lookup a non-existing session
        let session = repo.oauth2_session().lookup(Ulid::nil()).await.unwrap();
        assert_eq!(session, None);

        // Create an OAuth session at exchange time
        let session = repo
            .oauth2_session()
            .add_from_browser_session(
                &mut rng,
                &clock,
                &client,
                &user_session,
                grant.scope.clone(),
            )
            .await
            .unwrap();

        // Mark the grant as exchanged with the `OAuth2` session
        let grant = repo
            .oauth2_authorization_grant()
            .exchange(&clock, grant, &session)
            .await
            .unwrap();
        assert!(grant.is_exchanged());

        // Lookup the same session by id
        let session_lookup = repo
            .oauth2_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("session not found");
        assert_eq!(session, session_lookup);

        // Lookup a non-existing token
        let token = repo
            .oauth2_access_token()
            .lookup(Ulid::nil())
            .await
            .unwrap();
        assert_eq!(token, None);

        // Find a non-existing token
        let token = repo
            .oauth2_access_token()
            .find_by_token("aabbcc")
            .await
            .unwrap();
        assert_eq!(token, None);

        // Create an access token
        let access_token = repo
            .oauth2_access_token()
            .add(
                &mut rng,
                &clock,
                &session,
                "aabbcc".to_owned(),
                Some(Duration::try_minutes(5).unwrap()),
            )
            .await
            .unwrap();

        // Lookup the same token by id
        let access_token_lookup = repo
            .oauth2_access_token()
            .lookup(access_token.id)
            .await
            .unwrap()
            .expect("token not found");
        assert_eq!(access_token, access_token_lookup);

        // Find the same token by token
        let access_token_lookup = repo
            .oauth2_access_token()
            .find_by_token("aabbcc")
            .await
            .unwrap()
            .expect("token not found");
        assert_eq!(access_token, access_token_lookup);

        // Lookup a non-existing refresh token
        let refresh_token = repo
            .oauth2_refresh_token()
            .lookup(Ulid::nil())
            .await
            .unwrap();
        assert_eq!(refresh_token, None);

        // Find a non-existing refresh token
        let refresh_token = repo
            .oauth2_refresh_token()
            .find_by_token("aabbcc")
            .await
            .unwrap();
        assert_eq!(refresh_token, None);

        // Create a refresh token
        let refresh_token = repo
            .oauth2_refresh_token()
            .add(
                &mut rng,
                &clock,
                &session,
                &access_token,
                "aabbcc".to_owned(),
            )
            .await
            .unwrap();

        // Lookup the same refresh token by id
        let refresh_token_lookup = repo
            .oauth2_refresh_token()
            .lookup(refresh_token.id)
            .await
            .unwrap()
            .expect("refresh token not found");
        assert_eq!(refresh_token, refresh_token_lookup);

        // Find the same refresh token by token
        let refresh_token_lookup = repo
            .oauth2_refresh_token()
            .find_by_token("aabbcc")
            .await
            .unwrap()
            .expect("refresh token not found");
        assert_eq!(refresh_token, refresh_token_lookup);

        assert!(access_token.is_valid(clock.now()));
        clock.advance(Duration::try_minutes(6).unwrap());
        assert!(!access_token.is_valid(clock.now()));

        // XXX: we might want to create a new access token
        clock.advance(Duration::try_minutes(-6).unwrap()); // Go back in time
        assert!(access_token.is_valid(clock.now()));

        // Create a new refresh token to be able to consume the old one
        let new_refresh_token = repo
            .oauth2_refresh_token()
            .add(
                &mut rng,
                &clock,
                &session,
                &access_token,
                "ddeeff".to_owned(),
            )
            .await
            .unwrap();

        // Mark the access token as revoked
        let access_token = repo
            .oauth2_access_token()
            .revoke(&clock, access_token)
            .await
            .unwrap();
        assert!(!access_token.is_valid(clock.now()));

        // Mark the refresh token as consumed
        assert!(refresh_token.is_valid());
        let refresh_token = repo
            .oauth2_refresh_token()
            .consume(&clock, refresh_token, &new_refresh_token)
            .await
            .unwrap();
        assert!(!refresh_token.is_valid());

        // Record the user-agent on the session
        assert!(session.user_agent.is_none());
        let session = repo
            .oauth2_session()
            .record_user_agent(session, "Mozilla/5.0".to_owned())
            .await
            .unwrap();
        assert_eq!(session.user_agent.as_deref(), Some("Mozilla/5.0"));

        // Reload the session and check the user-agent
        let session = repo
            .oauth2_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("session not found");
        assert_eq!(session.user_agent.as_deref(), Some("Mozilla/5.0"));

        // Mark the session as finished
        assert!(session.is_valid());
        let session = repo.oauth2_session().finish(&clock, session).await.unwrap();
        assert!(!session.is_valid());
    }

    /// Test the [`OAuth2SessionRepository::list`] and
    /// [`OAuth2SessionRepository::count`] methods.
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_list_sessions(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create two users and their corresponding browser sessions
        let user1 = repo
            .user()
            .add(&mut rng, &clock, "alice".to_owned())
            .await
            .unwrap();
        let user1_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user1, None)
            .await
            .unwrap();

        let user2 = repo
            .user()
            .add(&mut rng, &clock, "bob".to_owned())
            .await
            .unwrap();
        let user2_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user2, None)
            .await
            .unwrap();

        // Create two clients
        let client1 = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://first.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("First client".to_owned()),
                Some("https://first.example.com/logo.png".parse().unwrap()),
                Some("https://first.example.com/".parse().unwrap()),
                Some("https://first.example.com/policy".parse().unwrap()),
                Some("https://first.example.com/tos".parse().unwrap()),
                Some("https://first.example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://first.example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();
        let client2 = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://second.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("Second client".to_owned()),
                Some("https://second.example.com/logo.png".parse().unwrap()),
                Some("https://second.example.com/".parse().unwrap()),
                Some("https://second.example.com/policy".parse().unwrap()),
                Some("https://second.example.com/tos".parse().unwrap()),
                Some("https://second.example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://second.example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        let scope = Scope::from_iter([OPENID, EMAIL]);
        let scope2 = Scope::from_iter([OPENID, PROFILE]);

        // Create two sessions for each user, one with each client
        // We're moving the clock forward by 1 minute between each session to ensure
        // we're getting consistent ordering in lists.
        let session11 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client1, &user1_session, scope.clone())
            .await
            .unwrap();
        clock.advance(Duration::try_minutes(1).unwrap());

        let session12 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client1, &user2_session, scope.clone())
            .await
            .unwrap();
        clock.advance(Duration::try_minutes(1).unwrap());

        let session21 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client2, &user1_session, scope2.clone())
            .await
            .unwrap();
        clock.advance(Duration::try_minutes(1).unwrap());

        let session22 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client2, &user2_session, scope2.clone())
            .await
            .unwrap();
        clock.advance(Duration::try_minutes(1).unwrap());

        // We're also finishing two of the sessions
        let session11 = repo
            .oauth2_session()
            .finish(&clock, session11)
            .await
            .unwrap();
        let session22 = repo
            .oauth2_session()
            .finish(&clock, session22)
            .await
            .unwrap();

        let pagination = Pagination::first(10);

        // First, list all the sessions
        let filter = OAuth2SessionFilter::new().for_any_user();
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 4);
        assert_eq!(list.edges[0].node, session11);
        assert_eq!(list.edges[1].node, session12);
        assert_eq!(list.edges[2].node, session21);
        assert_eq!(list.edges[3].node, session22);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 4);

        // Now filter for only one user
        let filter = OAuth2SessionFilter::new().for_user(&user1);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 2);
        assert_eq!(list.edges[0].node, session11);
        assert_eq!(list.edges[1].node, session21);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 2);

        // Filter for only one client
        let filter = OAuth2SessionFilter::new().for_client(&client1);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 2);
        assert_eq!(list.edges[0].node, session11);
        assert_eq!(list.edges[1].node, session12);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 2);

        // Filter for both a user and a client
        let filter = OAuth2SessionFilter::new()
            .for_user(&user2)
            .for_client(&client2);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node, session22);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 1);

        // Filter for active sessions
        let filter = OAuth2SessionFilter::new().active_only();
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 2);
        assert_eq!(list.edges[0].node, session12);
        assert_eq!(list.edges[1].node, session21);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 2);

        // Filter for finished sessions
        let filter = OAuth2SessionFilter::new().finished_only();
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 2);
        assert_eq!(list.edges[0].node, session11);
        assert_eq!(list.edges[1].node, session22);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 2);

        // Combine the finished filter with the user filter
        let filter = OAuth2SessionFilter::new().finished_only().for_user(&user2);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node, session22);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 1);

        // Combine the finished filter with the client filter
        let filter = OAuth2SessionFilter::new()
            .finished_only()
            .for_client(&client2);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node, session22);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 1);

        // Combine the active filter with the user filter
        let filter = OAuth2SessionFilter::new().active_only().for_user(&user2);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node, session12);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 1);

        // Combine the active filter with the client filter
        let filter = OAuth2SessionFilter::new()
            .active_only()
            .for_client(&client2);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node, session21);

        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 1);

        // Try the scope filter. We should get all sessions with the "openid" scope
        let scope = Scope::from_iter([OPENID]);
        let filter = OAuth2SessionFilter::new().with_scope(&scope);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 4);
        assert_eq!(list.edges[0].node, session11);
        assert_eq!(list.edges[1].node, session12);
        assert_eq!(list.edges[2].node, session21);
        assert_eq!(list.edges[3].node, session22);
        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 4);

        // We should get all sessions with the "openid" and "email" scope
        let scope = Scope::from_iter([OPENID, EMAIL]);
        let filter = OAuth2SessionFilter::new().with_scope(&scope);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 2);
        assert_eq!(list.edges[0].node, session11);
        assert_eq!(list.edges[1].node, session12);
        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 2);

        // Try combining the scope filter with the user filter
        let filter = OAuth2SessionFilter::new()
            .with_scope(&scope)
            .for_user(&user1);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node, session11);
        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 1);

        // Finish all sessions of a client in batch
        let affected = repo
            .oauth2_session()
            .finish_bulk(
                &clock,
                OAuth2SessionFilter::new()
                    .for_client(&client1)
                    .active_only(),
            )
            .await
            .unwrap();
        assert_eq!(affected, 1);

        // We should have 3 finished sessions
        assert_eq!(
            repo.oauth2_session()
                .count(OAuth2SessionFilter::new().finished_only())
                .await
                .unwrap(),
            3
        );

        // We should have 1 active sessions
        assert_eq!(
            repo.oauth2_session()
                .count(OAuth2SessionFilter::new().active_only())
                .await
                .unwrap(),
            1
        );
    }

    /// Test the created-at filters on [`OAuth2SessionFilter`].
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_list_sessions_by_created_at(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        let user = repo
            .user()
            .add(&mut rng, &clock, "alice".to_owned())
            .await
            .unwrap();
        let user_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("Test client".to_owned()),
                Some("https://example.com/logo.png".parse().unwrap()),
                Some("https://example.com/".parse().unwrap()),
                Some("https://example.com/policy".parse().unwrap()),
                Some("https://example.com/tos".parse().unwrap()),
                Some("https://example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        let scope = Scope::from_iter([OPENID]);

        // Create three sessions, one per minute, capturing the cutoff timestamp
        // between the second and the third.
        let session1 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client, &user_session, scope.clone())
            .await
            .unwrap();
        clock.advance(Duration::try_minutes(1).unwrap());

        let session2 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client, &user_session, scope.clone())
            .await
            .unwrap();
        clock.advance(Duration::try_minutes(1).unwrap());

        let cutoff = clock.now();

        clock.advance(Duration::try_minutes(1).unwrap());
        let session3 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client, &user_session, scope.clone())
            .await
            .unwrap();

        let pagination = Pagination::first(10);

        // Sessions created before the cutoff
        let filter = OAuth2SessionFilter::new().with_created_before(cutoff);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert_eq!(list.edges.len(), 2);
        assert_eq!(list.edges[0].node, session1);
        assert_eq!(list.edges[1].node, session2);
        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 2);

        // Sessions created after the cutoff
        let filter = OAuth2SessionFilter::new().with_created_after(cutoff);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node, session3);
        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 1);
    }

    /// Test the multi-client filter on [`OAuth2SessionFilter`].
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_list_sessions_for_clients(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Provision a user + browser session to attach the OAuth2 sessions to
        let user = repo
            .user()
            .add(&mut rng, &clock, "alice".to_owned())
            .await
            .unwrap();
        let user_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();

        // Provision three clients
        let mut clients = Vec::new();
        for label in ["first", "second", "third"] {
            let client = repo
                .oauth2_client()
                .add(
                    &mut rng,
                    &clock,
                    vec![
                        format!("https://{label}.example.com/redirect")
                            .parse()
                            .unwrap(),
                    ],
                    None,
                    None,
                    None,
                    vec![GrantType::AuthorizationCode],
                    Some(format!("{label} client")),
                    Some(
                        format!("https://{label}.example.com/logo.png")
                            .parse()
                            .unwrap(),
                    ),
                    Some(format!("https://{label}.example.com/").parse().unwrap()),
                    Some(
                        format!("https://{label}.example.com/policy")
                            .parse()
                            .unwrap(),
                    ),
                    Some(format!("https://{label}.example.com/tos").parse().unwrap()),
                    Some(
                        format!("https://{label}.example.com/jwks.json")
                            .parse()
                            .unwrap(),
                    ),
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(
                        format!("https://{label}.example.com/login")
                            .parse()
                            .unwrap(),
                    ),
                )
                .await
                .unwrap();
            clients.push(client);
        }
        let [client1, client2, client3] = <[_; 3]>::try_from(clients).ok().unwrap();

        let scope = Scope::from_iter([OPENID]);

        // One session per client
        let session1 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client1, &user_session, scope.clone())
            .await
            .unwrap();
        clock.advance(Duration::try_minutes(1).unwrap());

        let session2 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client2, &user_session, scope.clone())
            .await
            .unwrap();
        clock.advance(Duration::try_minutes(1).unwrap());

        let _session3 = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client3, &user_session, scope.clone())
            .await
            .unwrap();

        let pagination = Pagination::first(10);

        // Filter on two of the three clients returns the matching sessions
        let two_clients = [&client1, &client2];
        let filter = OAuth2SessionFilter::new().for_clients(&two_clients);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(!list.has_next_page);
        assert_eq!(list.edges.len(), 2);
        assert_eq!(list.edges[0].node, session1);
        assert_eq!(list.edges[1].node, session2);
        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 2);

        // A single-element list behaves like for_client
        let one_client = [&client2];
        let filter = OAuth2SessionFilter::new().for_clients(&one_client);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node, session2);
        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 1);

        // An empty list matches no sessions (sea-query emits `1 = 2` for IN ())
        let no_clients: [&mas_data_model::Client; 0] = [];
        let filter = OAuth2SessionFilter::new().for_clients(&no_clients);
        let list = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .unwrap();
        assert!(list.edges.is_empty());
        assert_eq!(repo.oauth2_session().count(filter).await.unwrap(), 0);
    }

    /// Test the [`OAuth2DeviceCodeGrantRepository`] implementation
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_device_code_grant_repository(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Provision a client
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("Example".to_owned()),
                Some("https://example.com/logo.png".parse().unwrap()),
                Some("https://example.com/".parse().unwrap()),
                Some("https://example.com/policy".parse().unwrap()),
                Some("https://example.com/tos".parse().unwrap()),
                Some("https://example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        // Provision a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        // Provision a browser session
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();

        let user_code = "usercode";
        let device_code = "devicecode";
        let scope = Scope::from_iter([OPENID, EMAIL]);

        // Create a device code grant
        let grant = repo
            .oauth2_device_code_grant()
            .add(
                &mut rng,
                &clock,
                OAuth2DeviceCodeGrantParams {
                    client: &client,
                    scope: scope.clone(),
                    device_code: device_code.to_owned(),
                    user_code: user_code.to_owned(),
                    expires_in: Duration::try_minutes(5).unwrap(),
                    ip_address: None,
                    user_agent: None,
                },
            )
            .await
            .unwrap();

        assert!(grant.is_pending());

        // Check that we can find the grant by ID
        let id = grant.id;
        let lookup = repo.oauth2_device_code_grant().lookup(id).await.unwrap();
        assert_eq!(lookup.as_ref(), Some(&grant));

        // Check that we can find the grant by device code
        let lookup = repo
            .oauth2_device_code_grant()
            .find_by_device_code(device_code)
            .await
            .unwrap();
        assert_eq!(lookup.as_ref(), Some(&grant));

        // Check that we can find the grant by user code
        let lookup = repo
            .oauth2_device_code_grant()
            .find_by_user_code(user_code)
            .await
            .unwrap();
        assert_eq!(lookup.as_ref(), Some(&grant));

        // Let's mark it as fulfilled, with a locale captured from the browser
        let grant = repo
            .oauth2_device_code_grant()
            .fulfill(&clock, grant, &browser_session, Some("en".to_owned()))
            .await
            .unwrap();
        assert!(!grant.is_pending());
        assert!(grant.is_fulfilled());
        assert_eq!(grant.locale.as_deref(), Some("en"));

        // Check that we can't mark it as rejected now
        let res = repo
            .oauth2_device_code_grant()
            .reject(&clock, grant, &browser_session)
            .await;
        assert!(res.is_err());

        // Look it up again
        let grant = repo
            .oauth2_device_code_grant()
            .lookup(id)
            .await
            .unwrap()
            .unwrap();

        // The locale was persisted
        assert_eq!(grant.locale.as_deref(), Some("en"));

        // We can't mark it as fulfilled again
        let res = repo
            .oauth2_device_code_grant()
            .fulfill(&clock, grant, &browser_session, None)
            .await;
        assert!(res.is_err());

        // Look it up again
        let grant = repo
            .oauth2_device_code_grant()
            .lookup(id)
            .await
            .unwrap()
            .unwrap();

        // Create an OAuth 2.0 session
        let session = repo
            .oauth2_session()
            .add_from_browser_session(&mut rng, &clock, &client, &browser_session, scope.clone())
            .await
            .unwrap();

        // We can mark it as exchanged
        let grant = repo
            .oauth2_device_code_grant()
            .exchange(&clock, grant, &session)
            .await
            .unwrap();
        assert!(!grant.is_pending());
        assert!(!grant.is_fulfilled());
        assert!(grant.is_exchanged());

        // We can't mark it as exchanged again
        let res = repo
            .oauth2_device_code_grant()
            .exchange(&clock, grant, &session)
            .await;
        assert!(res.is_err());

        // Do a new grant to reject it
        let grant = repo
            .oauth2_device_code_grant()
            .add(
                &mut rng,
                &clock,
                OAuth2DeviceCodeGrantParams {
                    client: &client,
                    scope: scope.clone(),
                    device_code: "second_devicecode".to_owned(),
                    user_code: "second_usercode".to_owned(),
                    expires_in: Duration::try_minutes(5).unwrap(),
                    ip_address: None,
                    user_agent: None,
                },
            )
            .await
            .unwrap();

        let id = grant.id;

        // We can mark it as rejected
        let grant = repo
            .oauth2_device_code_grant()
            .reject(&clock, grant, &browser_session)
            .await
            .unwrap();
        assert!(!grant.is_pending());
        assert!(grant.is_rejected());

        // We can't mark it as rejected again
        let res = repo
            .oauth2_device_code_grant()
            .reject(&clock, grant, &browser_session)
            .await;
        assert!(res.is_err());

        // Look it up again
        let grant = repo
            .oauth2_device_code_grant()
            .lookup(id)
            .await
            .unwrap()
            .unwrap();

        // We can't mark it as fulfilled
        let res = repo
            .oauth2_device_code_grant()
            .fulfill(&clock, grant, &browser_session, None)
            .await;
        assert!(res.is_err());

        // Look it up again
        let grant = repo
            .oauth2_device_code_grant()
            .lookup(id)
            .await
            .unwrap()
            .unwrap();

        // We can't mark it as exchanged
        let res = repo
            .oauth2_device_code_grant()
            .exchange(&clock, grant, &session)
            .await;
        assert!(res.is_err());
    }

    /// Test the [`OAuth2ClientRepository::list`] and
    /// [`OAuth2ClientRepository::count`] methods.
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_list_clients(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Empty initially
        let filter = OAuth2ClientFilter::new();
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 0);

        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert!(page.edges.is_empty());
        assert!(!page.has_next_page);

        // Add a couple of clients
        let client1 = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://first.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("First client".to_owned()),
                None,
                Some("https://first.example.com/".parse().unwrap()),
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
        clock.advance(Duration::try_minutes(1).unwrap());

        let client2 = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://second.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("Second client".to_owned()),
                None,
                Some("https://second.example.com/".parse().unwrap()),
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

        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 2);

        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert!(!page.has_next_page);
        assert_eq!(page.edges.len(), 2);
        assert_eq!(page.edges[0].node, client1);
        assert_eq!(page.edges[1].node, client2);

        // Add a static client
        let static_id = Ulid::from_datetime_with_rng(clock.now(), &mut rng);
        repo.oauth2_client()
            .upsert_static(
                static_id,
                Some("Static client".to_owned()),
                OAuthClientAuthenticationMethod::None,
                None,
                None,
                None,
                vec!["https://static.example.com/redirect".parse().unwrap()],
            )
            .await
            .unwrap();
        // Re-read via lookup so we have the canonical representation
        let static_client = repo
            .oauth2_client()
            .lookup(static_id)
            .await
            .unwrap()
            .expect("static client just inserted");

        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 3);

        // Only static clients
        let filter = OAuth2ClientFilter::new().only_static_clients();
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 1);
        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node, static_client);

        // Only dynamic clients
        let filter = OAuth2ClientFilter::new().only_dynamic_clients();
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 2);
        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 2);
        assert_eq!(page.edges[0].node, client1);
        assert_eq!(page.edges[1].node, client2);

        // Substring match on client_name
        let filter = OAuth2ClientFilter::new().matching_client_name("first");
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 1);
        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node, client1);

        // Case-insensitive match on client_name
        let filter = OAuth2ClientFilter::new().matching_client_name("CLIENT");
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 3);

        // Substring match on client_uri
        let filter = OAuth2ClientFilter::new().matching_client_uri("second");
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 1);
        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node, client2);

        // Case-insensitive match on client_uri
        let filter = OAuth2ClientFilter::new().matching_client_uri("EXAMPLE.COM");
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 2);
    }

    /// Test the grant-type filter on [`OAuth2ClientFilter`].
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_list_clients_by_grant_type(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // A client supporting authorization_code (+ refresh_token)
        let auth_code_client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://code.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                Some("Authorization code client".to_owned()),
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

        // A client supporting only client_credentials
        let client_credentials_client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec![],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("Client credentials client".to_owned()),
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

        // authorization_code: only the first client
        let filter = OAuth2ClientFilter::new().with_grant_type(&GrantType::AuthorizationCode);
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 1);
        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node, auth_code_client);

        // client_credentials: only the second client
        let filter = OAuth2ClientFilter::new().with_grant_type(&GrantType::ClientCredentials);
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 1);
        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node, client_credentials_client);

        // refresh_token: only the first client
        let filter = OAuth2ClientFilter::new().with_grant_type(&GrantType::RefreshToken);
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 1);

        // device_code: no client supports it
        let filter = OAuth2ClientFilter::new().with_grant_type(&GrantType::DeviceCode);
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 0);

        // A grant type without a dedicated column matches nothing
        let filter = OAuth2ClientFilter::new().with_grant_type(&GrantType::Implicit);
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 0);
    }

    /// Test the active-sessions filter on [`OAuth2ClientFilter`].
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_list_clients_by_active_sessions(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // A client that will have an active session
        let with_session = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec![],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("Client with session".to_owned()),
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

        // A client without any session
        let without_session = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec![],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("Client without session".to_owned()),
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
            .add_from_client_credentials(
                &mut rng,
                &clock,
                &with_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();

        // Has an active session: only the first client
        let filter = OAuth2ClientFilter::new().with_active_sessions(true);
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 1);
        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node, with_session);

        // Has no active session: only the second client
        let filter = OAuth2ClientFilter::new().with_active_sessions(false);
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 1);
        let page = repo
            .oauth2_client()
            .list(filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].node, without_session);

        // Once the session is finished, the first client no longer has one
        repo.oauth2_session().finish(&clock, session).await.unwrap();

        let filter = OAuth2ClientFilter::new().with_active_sessions(true);
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 0);
        let filter = OAuth2ClientFilter::new().with_active_sessions(false);
        assert_eq!(repo.oauth2_client().count(filter).await.unwrap(), 2);
    }
}
