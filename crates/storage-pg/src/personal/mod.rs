// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! A module containing the PostgreSQL implementations of the
//! Personal Access Token / Personal Session repositories

mod access_token;
mod session;

pub use access_token::PgPersonalAccessTokenRepository;
pub use session::PgPersonalSessionRepository;

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_data_model::{
        Clock, Device, clock::MockClock, personal::session::PersonalSessionOwner,
    };
    use mas_storage::{
        Pagination, RepositoryAccess,
        personal::{
            PersonalAccessTokenRepository, PersonalSessionFilter, PersonalSessionRepository,
        },
        user::UserRepository,
    };
    use oauth2_types::scope::{OPENID, PROFILE, Scope};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sqlx::PgPool;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_session_repository(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap();

        // Create a user
        let admin_user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();
        let bot_user = repo
            .user()
            .add(&mut rng, &clock, "marvin".to_owned())
            .await
            .unwrap();

        let all = PersonalSessionFilter::new().for_actor_user(&bot_user);
        let active = all.active_only();
        let finished = all.finished_only();
        let pagination = Pagination::first(10);

        assert_eq!(repo.personal_session().count(all).await.unwrap(), 0);
        assert_eq!(repo.personal_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.personal_session().count(finished).await.unwrap(), 0);

        // We start off with no sessions
        let full_list = repo.personal_session().list(all, pagination).await.unwrap();
        assert!(full_list.edges.is_empty());
        let active_list = repo
            .personal_session()
            .list(active, pagination)
            .await
            .unwrap();
        assert!(active_list.edges.is_empty());
        let finished_list = repo
            .personal_session()
            .list(finished, pagination)
            .await
            .unwrap();
        assert!(finished_list.edges.is_empty());

        // Start a personal session for that user
        let device = Device::generate(&mut rng);
        let scope: Scope = [OPENID, PROFILE]
            .into_iter()
            .chain(device.to_scope_token().unwrap())
            .collect();
        let session = repo
            .personal_session()
            .add(
                &mut rng,
                &clock,
                (&admin_user).into(),
                &bot_user,
                "Test Personal Session".to_owned(),
                scope.clone(),
            )
            .await
            .unwrap();
        assert_eq!(session.owner, PersonalSessionOwner::User(admin_user.id));
        assert_eq!(session.actor_user_id, bot_user.id);
        assert!(session.is_valid());
        assert!(!session.is_revoked());
        assert_eq!(session.scope, scope);

        assert_eq!(repo.personal_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.personal_session().count(active).await.unwrap(), 1);
        assert_eq!(repo.personal_session().count(finished).await.unwrap(), 0);

        let full_list = repo.personal_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(full_list.edges[0].node.0.id, session.id);
        assert!(full_list.edges[0].node.0.is_valid());
        let active_list = repo
            .personal_session()
            .list(active, pagination)
            .await
            .unwrap();
        assert_eq!(active_list.edges.len(), 1);
        assert_eq!(active_list.edges[0].node.0.id, session.id);
        assert!(active_list.edges[0].node.0.is_valid());
        let finished_list = repo
            .personal_session()
            .list(finished, pagination)
            .await
            .unwrap();
        assert!(finished_list.edges.is_empty());

        // Lookup the session and check it didn't change
        let session_lookup = repo
            .personal_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("personal session not found");
        assert_eq!(session_lookup.id, session.id);
        assert_eq!(
            session_lookup.owner,
            PersonalSessionOwner::User(admin_user.id)
        );
        assert_eq!(session_lookup.actor_user_id, bot_user.id);
        assert_eq!(session_lookup.scope, scope);
        assert!(session_lookup.is_valid());
        assert!(!session_lookup.is_revoked());

        // Revoke the session
        let session = repo
            .personal_session()
            .revoke(&clock, session)
            .await
            .unwrap();
        assert!(!session.is_valid());
        assert!(session.is_revoked());

        assert_eq!(repo.personal_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.personal_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.personal_session().count(finished).await.unwrap(), 1);

        let full_list = repo.personal_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(full_list.edges[0].node.0.id, session.id);
        let active_list = repo
            .personal_session()
            .list(active, pagination)
            .await
            .unwrap();
        assert!(active_list.edges.is_empty());
        let finished_list = repo
            .personal_session()
            .list(finished, pagination)
            .await
            .unwrap();
        assert_eq!(finished_list.edges.len(), 1);
        assert_eq!(finished_list.edges[0].node.0.id, session.id);
        assert!(finished_list.edges[0].node.0.is_revoked());

        // Reload the session and check again
        let session_lookup = repo
            .personal_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("personal session not found");
        assert!(!session_lookup.is_valid());
        assert!(session_lookup.is_revoked());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_access_token_repository(pool: PgPool) {
        const FIRST_TOKEN: &str = "first_access_token";
        const SECOND_TOKEN: &str = "second_access_token";
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create a user
        let admin_user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();
        let bot_user = repo
            .user()
            .add(&mut rng, &clock, "marvin".to_owned())
            .await
            .unwrap();

        // Start a personal session for that user
        let device = Device::generate(&mut rng);
        let scope: Scope = [OPENID, PROFILE]
            .into_iter()
            .chain(device.to_scope_token().unwrap())
            .collect();
        let session = repo
            .personal_session()
            .add(
                &mut rng,
                &clock,
                (&admin_user).into(),
                &bot_user,
                "Test Personal Session".to_owned(),
                scope,
            )
            .await
            .unwrap();

        // Add an access token to that session
        let token = repo
            .personal_access_token()
            .add(
                &mut rng,
                &clock,
                &session,
                FIRST_TOKEN,
                Some(Duration::try_minutes(1).unwrap()),
            )
            .await
            .unwrap();
        assert_eq!(token.session_id, session.id);

        // Commit the txn and grab a new transaction, to test a conflict
        repo.save().await.unwrap();

        {
            let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
            // Adding the same token a second time should conflict
            assert!(
                repo.personal_access_token()
                    .add(
                        &mut rng,
                        &clock,
                        &session,
                        FIRST_TOKEN,
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
            .personal_access_token()
            .lookup(token.id)
            .await
            .unwrap()
            .expect("personal access token not found");
        assert_eq!(token.id, token_lookup.id);
        assert_eq!(token_lookup.session_id, session.id);

        // Looking up via the token value works
        let token_lookup = repo
            .personal_access_token()
            .find_by_token(FIRST_TOKEN)
            .await
            .unwrap()
            .expect("personal access token not found");
        assert_eq!(token.id, token_lookup.id);
        assert_eq!(token_lookup.session_id, session.id);

        // Token is currently valid
        assert!(token.is_valid(clock.now()));

        clock.advance(Duration::try_minutes(1).unwrap());
        // Token should have expired
        assert!(!token.is_valid(clock.now()));

        // Add a second access token, this time without expiration
        let token = repo
            .personal_access_token()
            .add(&mut rng, &clock, &session, SECOND_TOKEN, None)
            .await
            .unwrap();
        assert_eq!(token.session_id, session.id);

        // Token is currently valid
        assert!(token.is_valid(clock.now()));

        // Revoke it
        let _token = repo
            .personal_access_token()
            .revoke(&clock, token)
            .await
            .unwrap();

        // Reload it
        let token = repo
            .personal_access_token()
            .find_by_token(SECOND_TOKEN)
            .await
            .unwrap()
            .expect("personal access token not found");

        // Token is not valid anymore
        assert!(!token.is_valid(clock.now()));

        repo.save().await.unwrap();
    }
}
