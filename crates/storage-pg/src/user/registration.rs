// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    UserEmailAuthentication, UserRegistration, UserRegistrationPassword, UserRegistrationToken,
};
use mas_storage::{Clock, user::UserRegistrationRepository};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseInconsistencyError, ExecuteExt as _};

/// An implementation of [`UserRegistrationRepository`] for a PostgreSQL
/// connection
pub struct PgUserRegistrationRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserRegistrationRepository<'c> {
    /// Create a new [`PgUserRegistrationRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct UserRegistrationLookup {
    user_registration_id: Uuid,
    ip_address: Option<IpAddr>,
    user_agent: Option<String>,
    post_auth_action: Option<serde_json::Value>,
    username: String,
    display_name: Option<String>,
    terms_url: Option<String>,
    email_authentication_id: Option<Uuid>,
    user_registration_token_id: Option<Uuid>,
    hashed_password: Option<String>,
    hashed_password_version: Option<i32>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl TryFrom<UserRegistrationLookup> for UserRegistration {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: UserRegistrationLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.user_registration_id);

        let password = match (value.hashed_password, value.hashed_password_version) {
            (Some(hashed_password), Some(version)) => {
                let version = version.try_into().map_err(|e| {
                    DatabaseInconsistencyError::on("user_registrations")
                        .column("hashed_password_version")
                        .row(id)
                        .source(e)
                })?;

                Some(UserRegistrationPassword {
                    hashed_password,
                    version,
                })
            }
            (None, None) => None,
            _ => {
                return Err(DatabaseInconsistencyError::on("user_registrations")
                    .column("hashed_password")
                    .row(id));
            }
        };

        let terms_url = value
            .terms_url
            .map(|u| u.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("user_registrations")
                    .column("terms_url")
                    .row(id)
                    .source(e)
            })?;

        Ok(UserRegistration {
            id,
            ip_address: value.ip_address,
            user_agent: value.user_agent,
            post_auth_action: value.post_auth_action,
            username: value.username,
            display_name: value.display_name,
            terms_url,
            email_authentication_id: value.email_authentication_id.map(Ulid::from),
            user_registration_token_id: value.user_registration_token_id.map(Ulid::from),
            password,
            created_at: value.created_at,
            completed_at: value.completed_at,
        })
    }
}

#[async_trait]
impl UserRegistrationRepository for PgUserRegistrationRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_registration.lookup",
        skip_all,
        fields(
            db.query.text,
            user_registration.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserRegistration>, Self::Error> {
        let res = sqlx::query_as!(
            UserRegistrationLookup,
            r#"
                SELECT user_registration_id
                     , ip_address as "ip_address: IpAddr"
                     , user_agent
                     , post_auth_action
                     , username
                     , display_name
                     , terms_url
                     , email_authentication_id
                     , user_registration_token_id
                     , hashed_password
                     , hashed_password_version
                     , created_at
                     , completed_at
                FROM user_registrations
                WHERE user_registration_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_registration.add",
        skip_all,
        fields(
            db.query.text,
            user_registration.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        post_auth_action: Option<serde_json::Value>,
    ) -> Result<UserRegistration, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_registration.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_registrations
                  ( user_registration_id
                  , ip_address
                  , user_agent
                  , post_auth_action
                  , username
                  , created_at
                  )
                VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::from(id),
            ip_address as Option<IpAddr>,
            user_agent.as_deref(),
            post_auth_action,
            username,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserRegistration {
            id,
            ip_address,
            user_agent,
            post_auth_action,
            created_at,
            completed_at: None,
            username,
            display_name: None,
            terms_url: None,
            email_authentication_id: None,
            user_registration_token_id: None,
            password: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_registration.set_display_name",
        skip_all,
        fields(
            db.query.text,
            user_registration.id = %user_registration.id,
            user_registration.display_name = display_name,
        ),
        err,
    )]
    async fn set_display_name(
        &mut self,
        mut user_registration: UserRegistration,
        display_name: String,
    ) -> Result<UserRegistration, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE user_registrations
                SET display_name = $2
                WHERE user_registration_id = $1 AND completed_at IS NULL
            "#,
            Uuid::from(user_registration.id),
            display_name,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_registration.display_name = Some(display_name);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_terms_url",
        skip_all,
        fields(
            db.query.text,
            user_registration.id = %user_registration.id,
            user_registration.terms_url = %terms_url,
        ),
        err,
    )]
    async fn set_terms_url(
        &mut self,
        mut user_registration: UserRegistration,
        terms_url: Url,
    ) -> Result<UserRegistration, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE user_registrations
                SET terms_url = $2
                WHERE user_registration_id = $1 AND completed_at IS NULL
            "#,
            Uuid::from(user_registration.id),
            terms_url.as_str(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_registration.terms_url = Some(terms_url);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_email_authentication",
        skip_all,
        fields(
            db.query.text,
            %user_registration.id,
            %user_email_authentication.id,
            %user_email_authentication.email,
        ),
        err,
    )]
    async fn set_email_authentication(
        &mut self,
        mut user_registration: UserRegistration,
        user_email_authentication: &UserEmailAuthentication,
    ) -> Result<UserRegistration, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE user_registrations
                SET email_authentication_id = $2
                WHERE user_registration_id = $1 AND completed_at IS NULL
            "#,
            Uuid::from(user_registration.id),
            Uuid::from(user_email_authentication.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_registration.email_authentication_id = Some(user_email_authentication.id);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_password",
        skip_all,
        fields(
            db.query.text,
            user_registration.id = %user_registration.id,
            user_registration.hashed_password = hashed_password,
            user_registration.hashed_password_version = version,
        ),
        err,
    )]
    async fn set_password(
        &mut self,
        mut user_registration: UserRegistration,
        hashed_password: String,
        version: u16,
    ) -> Result<UserRegistration, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE user_registrations
                SET hashed_password = $2, hashed_password_version = $3
                WHERE user_registration_id = $1 AND completed_at IS NULL
            "#,
            Uuid::from(user_registration.id),
            hashed_password,
            i32::from(version),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_registration.password = Some(UserRegistrationPassword {
            hashed_password,
            version,
        });

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.set_registration_token",
        skip_all,
        fields(
            db.query.text,
            %user_registration.id,
            %user_registration_token.id,
        ),
        err,
    )]
    async fn set_registration_token(
        &mut self,
        mut user_registration: UserRegistration,
        user_registration_token: &UserRegistrationToken,
    ) -> Result<UserRegistration, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE user_registrations
                SET user_registration_token_id = $2
                WHERE user_registration_id = $1 AND completed_at IS NULL
            "#,
            Uuid::from(user_registration.id),
            Uuid::from(user_registration_token.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_registration.user_registration_token_id = Some(user_registration_token.id);

        Ok(user_registration)
    }

    #[tracing::instrument(
        name = "db.user_registration.complete",
        skip_all,
        fields(
            db.query.text,
            user_registration.id = %user_registration.id,
        ),
        err,
    )]
    async fn complete(
        &mut self,
        clock: &dyn Clock,
        mut user_registration: UserRegistration,
    ) -> Result<UserRegistration, Self::Error> {
        let completed_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE user_registrations
                SET completed_at = $2
                WHERE user_registration_id = $1 AND completed_at IS NULL
            "#,
            Uuid::from(user_registration.id),
            completed_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_registration.completed_at = Some(completed_at);

        Ok(user_registration)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use mas_data_model::UserRegistrationPassword;
    use mas_storage::{Clock, clock::MockClock};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sqlx::PgPool;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_create_lookup_complete(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.created_at, clock.now());
        assert_eq!(registration.completed_at, None);
        assert_eq!(registration.username, "alice");
        assert_eq!(registration.display_name, None);
        assert_eq!(registration.terms_url, None);
        assert_eq!(registration.email_authentication_id, None);
        assert_eq!(registration.password, None);
        assert_eq!(registration.user_agent, None);
        assert_eq!(registration.ip_address, None);
        assert_eq!(registration.post_auth_action, None);

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.id, registration.id);
        assert_eq!(lookup.created_at, registration.created_at);
        assert_eq!(lookup.completed_at, registration.completed_at);
        assert_eq!(lookup.username, registration.username);
        assert_eq!(lookup.display_name, registration.display_name);
        assert_eq!(lookup.terms_url, registration.terms_url);
        assert_eq!(
            lookup.email_authentication_id,
            registration.email_authentication_id
        );
        assert_eq!(lookup.password, registration.password);
        assert_eq!(lookup.user_agent, registration.user_agent);
        assert_eq!(lookup.ip_address, registration.ip_address);
        assert_eq!(lookup.post_auth_action, registration.post_auth_action);

        // Mark the registration as completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();
        assert_eq!(registration.completed_at, Some(clock.now()));

        // Lookup the registration again
        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lookup.completed_at, registration.completed_at);

        // Do it again, it should fail
        let res = repo
            .user_registration()
            .complete(&clock, registration)
            .await;
        assert!(res.is_err());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_create_useragent_ipaddress(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        let registration = repo
            .user_registration()
            .add(
                &mut rng,
                &clock,
                "alice".to_owned(),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                Some("Mozilla/5.0".to_owned()),
                Some(serde_json::json!({"action": "continue_compat_sso_login", "id": "01FSHN9AG0MKGTBNZ16RDR3PVY"})),
            )
            .await
            .unwrap();

        assert_eq!(registration.user_agent, Some("Mozilla/5.0".to_owned()));
        assert_eq!(
            registration.ip_address,
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert_eq!(
            registration.post_auth_action,
            Some(
                serde_json::json!({"action": "continue_compat_sso_login", "id": "01FSHN9AG0MKGTBNZ16RDR3PVY"})
            )
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.user_agent, registration.user_agent);
        assert_eq!(lookup.ip_address, registration.ip_address);
        assert_eq!(lookup.post_auth_action, registration.post_auth_action);
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_set_display_name(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.display_name, None);

        let registration = repo
            .user_registration()
            .set_display_name(registration, "Alice".to_owned())
            .await
            .unwrap();

        assert_eq!(registration.display_name, Some("Alice".to_owned()));

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.display_name, registration.display_name);

        // Setting it again should work
        let registration = repo
            .user_registration()
            .set_display_name(registration, "Bob".to_owned())
            .await
            .unwrap();

        assert_eq!(registration.display_name, Some("Bob".to_owned()));

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.display_name, registration.display_name);

        // Can't set it once completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();

        let res = repo
            .user_registration()
            .set_display_name(registration, "Charlie".to_owned())
            .await;
        assert!(res.is_err());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_set_terms_url(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.terms_url, None);

        let registration = repo
            .user_registration()
            .set_terms_url(registration, "https://example.com/terms".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(
            registration.terms_url,
            Some("https://example.com/terms".parse().unwrap())
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.terms_url, registration.terms_url);

        // Setting it again should work
        let registration = repo
            .user_registration()
            .set_terms_url(registration, "https://example.com/terms2".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(
            registration.terms_url,
            Some("https://example.com/terms2".parse().unwrap())
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.terms_url, registration.terms_url);

        // Can't set it once completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();

        let res = repo
            .user_registration()
            .set_terms_url(registration, "https://example.com/terms3".parse().unwrap())
            .await;
        assert!(res.is_err());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_set_email_authentication(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.email_authentication_id, None);

        let authentication = repo
            .user_email()
            .add_authentication_for_registration(
                &mut rng,
                &clock,
                "alice@example.com".to_owned(),
                &registration,
            )
            .await
            .unwrap();

        let registration = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await
            .unwrap();

        assert_eq!(
            registration.email_authentication_id,
            Some(authentication.id)
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            lookup.email_authentication_id,
            registration.email_authentication_id
        );

        // Setting it again should work
        let registration = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await
            .unwrap();

        assert_eq!(
            registration.email_authentication_id,
            Some(authentication.id)
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            lookup.email_authentication_id,
            registration.email_authentication_id
        );

        // Can't set it once completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();

        let res = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await;
        assert!(res.is_err());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_set_password(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        let registration = repo
            .user_registration()
            .add(&mut rng, &clock, "alice".to_owned(), None, None, None)
            .await
            .unwrap();

        assert_eq!(registration.password, None);

        let registration = repo
            .user_registration()
            .set_password(registration, "fakehashedpassword".to_owned(), 1)
            .await
            .unwrap();

        assert_eq!(
            registration.password,
            Some(UserRegistrationPassword {
                hashed_password: "fakehashedpassword".to_owned(),
                version: 1,
            })
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.password, registration.password);

        // Setting it again should work
        let registration = repo
            .user_registration()
            .set_password(registration, "fakehashedpassword2".to_owned(), 2)
            .await
            .unwrap();

        assert_eq!(
            registration.password,
            Some(UserRegistrationPassword {
                hashed_password: "fakehashedpassword2".to_owned(),
                version: 2,
            })
        );

        let lookup = repo
            .user_registration()
            .lookup(registration.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lookup.password, registration.password);

        // Can't set it once completed
        let registration = repo
            .user_registration()
            .complete(&clock, registration)
            .await
            .unwrap();

        let res = repo
            .user_registration()
            .set_password(registration, "fakehashedpassword3".to_owned(), 3)
            .await;
        assert!(res.is_err());
    }
}
