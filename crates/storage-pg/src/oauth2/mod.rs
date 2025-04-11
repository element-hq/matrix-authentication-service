// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

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
    use mas_data_model::{AuthorizationCode, UserAgent};
    use mas_storage::{
        Clock, Pagination,
        clock::MockClock,
        oauth2::{OAuth2DeviceCodeGrantParams, OAuth2SessionFilter, OAuth2SessionRepository},
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
            )
            .await
            .unwrap();
        assert!(grant.is_pending());

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

        // Lookup a non-existing session
        let session = repo.oauth2_session().lookup(Ulid::nil()).await.unwrap();
        assert_eq!(session, None);

        // Create an OAuth session
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

        // Mark the grant as fulfilled
        let grant = repo
            .oauth2_authorization_grant()
            .fulfill(&clock, &session, grant)
            .await
            .unwrap();
        assert!(grant.is_fulfilled());

        // Lookup the same session by id
        let session_lookup = repo
            .oauth2_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("session not found");
        assert_eq!(session, session_lookup);

        // Mark the grant as exchanged
        let grant = repo
            .oauth2_authorization_grant()
            .exchange(&clock, grant)
            .await
            .unwrap();
        assert!(grant.is_exchanged());

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
            .record_user_agent(session, UserAgent::parse("Mozilla/5.0".to_owned()))
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
        assert_eq!(list.edges[0], session11);
        assert_eq!(list.edges[1], session12);
        assert_eq!(list.edges[2], session21);
        assert_eq!(list.edges[3], session22);

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
        assert_eq!(list.edges[0], session11);
        assert_eq!(list.edges[1], session21);

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
        assert_eq!(list.edges[0], session11);
        assert_eq!(list.edges[1], session12);

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
        assert_eq!(list.edges[0], session22);

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
        assert_eq!(list.edges[0], session12);
        assert_eq!(list.edges[1], session21);

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
        assert_eq!(list.edges[0], session11);
        assert_eq!(list.edges[1], session22);

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
        assert_eq!(list.edges[0], session22);

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
        assert_eq!(list.edges[0], session22);

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
        assert_eq!(list.edges[0], session12);

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
        assert_eq!(list.edges[0], session21);

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
        assert_eq!(list.edges[0], session11);
        assert_eq!(list.edges[1], session12);
        assert_eq!(list.edges[2], session21);
        assert_eq!(list.edges[3], session22);
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
        assert_eq!(list.edges[0], session11);
        assert_eq!(list.edges[1], session12);
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
        assert_eq!(list.edges[0], session11);
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

        // Let's mark it as fulfilled
        let grant = repo
            .oauth2_device_code_grant()
            .fulfill(&clock, grant, &browser_session)
            .await
            .unwrap();
        assert!(!grant.is_pending());
        assert!(grant.is_fulfilled());

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

        // We can't mark it as fulfilled again
        let res = repo
            .oauth2_device_code_grant()
            .fulfill(&clock, grant, &browser_session)
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
            .fulfill(&clock, grant, &browser_session)
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
}
