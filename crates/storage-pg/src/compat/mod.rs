// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! A module containing PostgreSQL implementation of repositories for the
//! compatibility layer

mod access_token;
mod refresh_token;
mod session;
mod sso_login;

pub use self::{
    access_token::PgCompatAccessTokenRepository, refresh_token::PgCompatRefreshTokenRepository,
    session::PgCompatSessionRepository, sso_login::PgCompatSsoLoginRepository,
};

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_data_model::{Clock, Device, clock::MockClock};
    use mas_storage::{
        Pagination, RepositoryAccess,
        compat::{
            CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionFilter,
            CompatSessionRepository, CompatSsoLoginFilter,
        },
        user::UserRepository,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_session_repository(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        let all = CompatSessionFilter::new().for_user(&user);
        let active = all.active_only();
        let finished = all.finished_only();
        let pagination = Pagination::first(10);

        assert_eq!(repo.compat_session().count(all).await.unwrap(), 0);
        assert_eq!(repo.compat_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.compat_session().count(finished).await.unwrap(), 0);

        let full_list = repo.compat_session().list(all, pagination).await.unwrap();
        assert!(full_list.edges.is_empty());
        let active_list = repo
            .compat_session()
            .list(active, pagination)
            .await
            .unwrap();
        assert!(active_list.edges.is_empty());
        let finished_list = repo
            .compat_session()
            .list(finished, pagination)
            .await
            .unwrap();
        assert!(finished_list.edges.is_empty());

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let device_str = device.as_str().to_owned();
        let session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device.clone(), None, false, None)
            .await
            .unwrap();
        assert_eq!(session.user_id, user.id);
        assert_eq!(session.device.as_ref().unwrap().as_str(), device_str);
        assert!(session.is_valid());
        assert!(!session.is_finished());

        assert_eq!(repo.compat_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.compat_session().count(active).await.unwrap(), 1);
        assert_eq!(repo.compat_session().count(finished).await.unwrap(), 0);

        let full_list = repo.compat_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(full_list.edges[0].node.0.id, session.id);
        let active_list = repo
            .compat_session()
            .list(active, pagination)
            .await
            .unwrap();
        assert_eq!(active_list.edges.len(), 1);
        assert_eq!(active_list.edges[0].node.0.id, session.id);
        let finished_list = repo
            .compat_session()
            .list(finished, pagination)
            .await
            .unwrap();
        assert!(finished_list.edges.is_empty());

        // Lookup the session and check it didn't change
        let session_lookup = repo
            .compat_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("compat session not found");
        assert_eq!(session_lookup.id, session.id);
        assert_eq!(session_lookup.user_id, user.id);
        assert_eq!(session.device.as_ref().unwrap().as_str(), device_str);
        assert!(session_lookup.is_valid());
        assert!(!session_lookup.is_finished());

        // Record a user-agent for the session
        assert!(session_lookup.user_agent.is_none());
        let session = repo
            .compat_session()
            .record_user_agent(session_lookup, "Mozilla/5.0".to_owned())
            .await
            .unwrap();
        assert_eq!(session.user_agent.as_deref(), Some("Mozilla/5.0"));

        // Reload the session and check again
        let session_lookup = repo
            .compat_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("compat session not found");
        assert_eq!(session_lookup.user_agent.as_deref(), Some("Mozilla/5.0"));

        // Look up the session by device
        let list = repo
            .compat_session()
            .list(
                CompatSessionFilter::new()
                    .for_user(&user)
                    .for_device(&device),
                pagination,
            )
            .await
            .unwrap();
        assert_eq!(list.edges.len(), 1);
        let session_lookup = &list.edges[0].node.0;
        assert_eq!(session_lookup.id, session.id);
        assert_eq!(session_lookup.user_id, user.id);
        assert_eq!(session.device.as_ref().unwrap().as_str(), device_str);
        assert!(session_lookup.is_valid());
        assert!(!session_lookup.is_finished());

        // Finish the session
        let session = repo.compat_session().finish(&clock, session).await.unwrap();
        assert!(!session.is_valid());
        assert!(session.is_finished());

        assert_eq!(repo.compat_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.compat_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.compat_session().count(finished).await.unwrap(), 1);

        let full_list = repo.compat_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(full_list.edges[0].node.0.id, session.id);
        let active_list = repo
            .compat_session()
            .list(active, pagination)
            .await
            .unwrap();
        assert!(active_list.edges.is_empty());
        let finished_list = repo
            .compat_session()
            .list(finished, pagination)
            .await
            .unwrap();
        assert_eq!(finished_list.edges.len(), 1);
        assert_eq!(finished_list.edges[0].node.0.id, session.id);

        // Reload the session and check again
        let session_lookup = repo
            .compat_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("compat session not found");
        assert!(!session_lookup.is_valid());
        assert!(session_lookup.is_finished());

        // Now add another session, with an SSO login this time
        let unknown_session = session;
        // Start a new SSO login
        let login = repo
            .compat_sso_login()
            .add(
                &mut rng,
                &clock,
                "login-token".to_owned(),
                "https://example.com/callback".parse().unwrap(),
            )
            .await
            .unwrap();
        assert!(login.is_pending());

        // Start a browser session for the user
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let sso_login_session = repo
            .compat_session()
            .add(
                &mut rng,
                &clock,
                &user,
                device,
                Some(&browser_session),
                false,
                None,
            )
            .await
            .unwrap();

        // Associate the login with the session
        let login = repo
            .compat_sso_login()
            .fulfill(&clock, login, &browser_session)
            .await
            .unwrap();
        assert!(login.is_fulfilled());
        let login = repo
            .compat_sso_login()
            .exchange(&clock, login, &sso_login_session)
            .await
            .unwrap();
        assert!(login.is_exchanged());

        // Now query the session list with both the unknown and SSO login session type
        // filter
        let all = CompatSessionFilter::new().for_user(&user);
        let sso_login = all.sso_login_only();
        let unknown = all.unknown_only();
        assert_eq!(repo.compat_session().count(all).await.unwrap(), 2);
        assert_eq!(repo.compat_session().count(sso_login).await.unwrap(), 1);
        assert_eq!(repo.compat_session().count(unknown).await.unwrap(), 1);

        let list = repo
            .compat_session()
            .list(sso_login, pagination)
            .await
            .unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node.0.id, sso_login_session.id);
        let list = repo
            .compat_session()
            .list(unknown, pagination)
            .await
            .unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(list.edges[0].node.0.id, unknown_session.id);

        // Check that combining the two filters works
        // At this point, there is one active SSO login session and one finished unknown
        // session
        assert_eq!(
            repo.compat_session()
                .count(all.sso_login_only().active_only())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repo.compat_session()
                .count(all.sso_login_only().finished_only())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            repo.compat_session()
                .count(all.unknown_only().active_only())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            repo.compat_session()
                .count(all.unknown_only().finished_only())
                .await
                .unwrap(),
            1
        );

        // Check that we can batch finish sessions
        let affected = repo
            .compat_session()
            .finish_bulk(&clock, all.sso_login_only().active_only())
            .await
            .unwrap();
        assert_eq!(affected, 1);
        assert_eq!(repo.compat_session().count(finished).await.unwrap(), 2);
        assert_eq!(repo.compat_session().count(active).await.unwrap(), 0);
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_access_token_repository(pool: PgPool) {
        const FIRST_TOKEN: &str = "first_access_token";
        const SECOND_TOKEN: &str = "second_access_token";
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device, None, false, None)
            .await
            .unwrap();

        // Add an access token to that session
        let token = repo
            .compat_access_token()
            .add(
                &mut rng,
                &clock,
                &session,
                FIRST_TOKEN.to_owned(),
                Some(Duration::try_minutes(1).unwrap()),
            )
            .await
            .unwrap();
        assert_eq!(token.session_id, session.id);
        assert_eq!(token.token, FIRST_TOKEN);

        // Commit the txn and grab a new transaction, to test a conflict
        repo.save().await.unwrap();

        {
            let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
            // Adding the same token a second time should conflict
            assert!(
                repo.compat_access_token()
                    .add(
                        &mut rng,
                        &clock,
                        &session,
                        FIRST_TOKEN.to_owned(),
                        Some(Duration::try_minutes(1).unwrap()),
                    )
                    .await
                    .is_err()
            );
            repo.cancel().await.unwrap();
        }

        // Grab a new repo
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Looking up via ID works
        let token_lookup = repo
            .compat_access_token()
            .lookup(token.id)
            .await
            .unwrap()
            .expect("compat access token not found");
        assert_eq!(token.id, token_lookup.id);
        assert_eq!(token_lookup.session_id, session.id);

        // Looking up via the token value works
        let token_lookup = repo
            .compat_access_token()
            .find_by_token(FIRST_TOKEN)
            .await
            .unwrap()
            .expect("compat access token not found");
        assert_eq!(token.id, token_lookup.id);
        assert_eq!(token_lookup.session_id, session.id);

        // Token is currently valid
        assert!(token.is_valid(clock.now()));

        clock.advance(Duration::try_minutes(1).unwrap());
        // Token should have expired
        assert!(!token.is_valid(clock.now()));

        // Add a second access token, this time without expiration
        let token = repo
            .compat_access_token()
            .add(&mut rng, &clock, &session, SECOND_TOKEN.to_owned(), None)
            .await
            .unwrap();
        assert_eq!(token.session_id, session.id);
        assert_eq!(token.token, SECOND_TOKEN);

        // Token is currently valid
        assert!(token.is_valid(clock.now()));

        // Make it expire
        repo.compat_access_token()
            .expire(&clock, token)
            .await
            .unwrap();

        // Reload it
        let token = repo
            .compat_access_token()
            .find_by_token(SECOND_TOKEN)
            .await
            .unwrap()
            .expect("compat access token not found");

        // Token is not valid anymore
        assert!(!token.is_valid(clock.now()));

        repo.save().await.unwrap();
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_refresh_token_repository(pool: PgPool) {
        const ACCESS_TOKEN: &str = "access_token";
        const REFRESH_TOKEN: &str = "refresh_token";
        const REFRESH_TOKEN2: &str = "refresh_token2";
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device, None, false, None)
            .await
            .unwrap();

        // Add an access token to that session
        let access_token = repo
            .compat_access_token()
            .add(&mut rng, &clock, &session, ACCESS_TOKEN.to_owned(), None)
            .await
            .unwrap();

        let refresh_token = repo
            .compat_refresh_token()
            .add(
                &mut rng,
                &clock,
                &session,
                &access_token,
                REFRESH_TOKEN.to_owned(),
            )
            .await
            .unwrap();
        assert_eq!(refresh_token.session_id, session.id);
        assert_eq!(refresh_token.access_token_id, access_token.id);
        assert_eq!(refresh_token.token, REFRESH_TOKEN);
        assert!(refresh_token.is_valid());
        assert!(!refresh_token.is_consumed());

        // Look it up by ID and check everything matches
        let refresh_token_lookup = repo
            .compat_refresh_token()
            .lookup(refresh_token.id)
            .await
            .unwrap()
            .expect("refresh token not found");
        assert_eq!(refresh_token_lookup.id, refresh_token.id);
        assert_eq!(refresh_token_lookup.session_id, session.id);
        assert_eq!(refresh_token_lookup.access_token_id, access_token.id);
        assert_eq!(refresh_token_lookup.token, REFRESH_TOKEN);
        assert!(refresh_token_lookup.is_valid());
        assert!(!refresh_token_lookup.is_consumed());

        // Look it up by token and check everything matches
        let refresh_token_lookup = repo
            .compat_refresh_token()
            .find_by_token(REFRESH_TOKEN)
            .await
            .unwrap()
            .expect("refresh token not found");
        assert_eq!(refresh_token_lookup.id, refresh_token.id);
        assert_eq!(refresh_token_lookup.session_id, session.id);
        assert_eq!(refresh_token_lookup.access_token_id, access_token.id);
        assert_eq!(refresh_token_lookup.token, REFRESH_TOKEN);
        assert!(refresh_token_lookup.is_valid());
        assert!(!refresh_token_lookup.is_consumed());

        // Consume the first token, but to do so we need a 2nd to replace it with
        let refresh_token2 = repo
            .compat_refresh_token()
            .add(
                &mut rng,
                &clock,
                &session,
                &access_token,
                REFRESH_TOKEN2.to_owned(),
            )
            .await
            .unwrap();

        let refresh_token = repo
            .compat_refresh_token()
            .consume_and_replace(&clock, refresh_token, &refresh_token2)
            .await
            .unwrap();
        assert!(!refresh_token.is_valid());
        assert!(refresh_token.is_consumed());

        // Reload the first token and check again
        let refresh_token_lookup = repo
            .compat_refresh_token()
            .find_by_token(REFRESH_TOKEN)
            .await
            .unwrap()
            .expect("refresh token not found");
        assert!(!refresh_token_lookup.is_valid());
        assert!(refresh_token_lookup.is_consumed());

        // Consuming it again should not work
        assert!(
            repo.compat_refresh_token()
                .consume_and_replace(&clock, refresh_token, &refresh_token2)
                .await
                .is_err()
        );

        repo.save().await.unwrap();
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_compat_sso_login_repository(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        // Lookup an unknown SSO login
        let login = repo.compat_sso_login().lookup(Ulid::nil()).await.unwrap();
        assert_eq!(login, None);

        let all = CompatSsoLoginFilter::new();
        let for_user = all.for_user(&user);
        let pending = all.pending_only();
        let fulfilled = all.fulfilled_only();
        let exchanged = all.exchanged_only();

        // Check the initial counts
        assert_eq!(repo.compat_sso_login().count(all).await.unwrap(), 0);
        assert_eq!(repo.compat_sso_login().count(for_user).await.unwrap(), 0);
        assert_eq!(repo.compat_sso_login().count(pending).await.unwrap(), 0);
        assert_eq!(repo.compat_sso_login().count(fulfilled).await.unwrap(), 0);
        assert_eq!(repo.compat_sso_login().count(exchanged).await.unwrap(), 0);

        // Lookup an unknown login token
        let login = repo
            .compat_sso_login()
            .find_by_token("login-token")
            .await
            .unwrap();
        assert_eq!(login, None);

        // Start a new SSO login
        let login = repo
            .compat_sso_login()
            .add(
                &mut rng,
                &clock,
                "login-token".to_owned(),
                "https://example.com/callback".parse().unwrap(),
            )
            .await
            .unwrap();
        assert!(login.is_pending());

        // Check the counts
        assert_eq!(repo.compat_sso_login().count(all).await.unwrap(), 1);
        assert_eq!(repo.compat_sso_login().count(for_user).await.unwrap(), 0);
        assert_eq!(repo.compat_sso_login().count(pending).await.unwrap(), 1);
        assert_eq!(repo.compat_sso_login().count(fulfilled).await.unwrap(), 0);
        assert_eq!(repo.compat_sso_login().count(exchanged).await.unwrap(), 0);

        // Lookup the login by ID
        let login_lookup = repo
            .compat_sso_login()
            .lookup(login.id)
            .await
            .unwrap()
            .expect("login not found");
        assert_eq!(login_lookup, login);

        // Find the login by token
        let login_lookup = repo
            .compat_sso_login()
            .find_by_token("login-token")
            .await
            .unwrap()
            .expect("login not found");
        assert_eq!(login_lookup, login);

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let compat_session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device, None, false, None)
            .await
            .unwrap();

        // Exchanging before fulfilling should not work
        // Note: It should also not poison the SQL transaction
        let res = repo
            .compat_sso_login()
            .exchange(&clock, login.clone(), &compat_session)
            .await;
        assert!(res.is_err());

        // Start a browser session for that user
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();

        // Associate the login with the session
        let login = repo
            .compat_sso_login()
            .fulfill(&clock, login, &browser_session)
            .await
            .unwrap();
        assert!(login.is_fulfilled());

        // Check the counts
        assert_eq!(repo.compat_sso_login().count(all).await.unwrap(), 1);
        assert_eq!(repo.compat_sso_login().count(for_user).await.unwrap(), 1);
        assert_eq!(repo.compat_sso_login().count(pending).await.unwrap(), 0);
        assert_eq!(repo.compat_sso_login().count(fulfilled).await.unwrap(), 1);
        assert_eq!(repo.compat_sso_login().count(exchanged).await.unwrap(), 0);

        // Fulfilling again should not work
        // Note: It should also not poison the SQL transaction
        let res = repo
            .compat_sso_login()
            .fulfill(&clock, login.clone(), &browser_session)
            .await;
        assert!(res.is_err());

        // Exchange that login
        let login = repo
            .compat_sso_login()
            .exchange(&clock, login, &compat_session)
            .await
            .unwrap();
        assert!(login.is_exchanged());

        // Check the counts
        assert_eq!(repo.compat_sso_login().count(all).await.unwrap(), 1);
        assert_eq!(repo.compat_sso_login().count(for_user).await.unwrap(), 1);
        assert_eq!(repo.compat_sso_login().count(pending).await.unwrap(), 0);
        assert_eq!(repo.compat_sso_login().count(fulfilled).await.unwrap(), 0);
        assert_eq!(repo.compat_sso_login().count(exchanged).await.unwrap(), 1);

        // Exchange again should not work
        // Note: It should also not poison the SQL transaction
        let res = repo
            .compat_sso_login()
            .exchange(&clock, login.clone(), &compat_session)
            .await;
        assert!(res.is_err());

        // Fulfilling after exchanging should not work
        // Note: It should also not poison the SQL transaction
        let res = repo
            .compat_sso_login()
            .fulfill(&clock, login.clone(), &browser_session)
            .await;
        assert!(res.is_err());

        let pagination = Pagination::first(10);

        // List all logins
        let logins = repo.compat_sso_login().list(all, pagination).await.unwrap();
        assert!(!logins.has_next_page);
        assert_eq!(logins.edges.len(), 1);
        assert_eq!(logins.edges[0].node, login);

        // List the logins for the user
        let logins = repo
            .compat_sso_login()
            .list(for_user, pagination)
            .await
            .unwrap();
        assert!(!logins.has_next_page);
        assert_eq!(logins.edges.len(), 1);
        assert_eq!(logins.edges[0].node, login);

        // List only the pending logins for the user
        let logins = repo
            .compat_sso_login()
            .list(for_user.pending_only(), pagination)
            .await
            .unwrap();
        assert!(!logins.has_next_page);
        assert!(logins.edges.is_empty());

        // List only the fulfilled logins for the user
        let logins = repo
            .compat_sso_login()
            .list(for_user.fulfilled_only(), pagination)
            .await
            .unwrap();
        assert!(!logins.has_next_page);
        assert!(logins.edges.is_empty());

        // List only the exchanged logins for the user
        let logins = repo
            .compat_sso_login()
            .list(for_user.exchanged_only(), pagination)
            .await
            .unwrap();
        assert!(!logins.has_next_page);
        assert_eq!(logins.edges.len(), 1);
        assert_eq!(logins.edges[0].node, login);
    }
}
