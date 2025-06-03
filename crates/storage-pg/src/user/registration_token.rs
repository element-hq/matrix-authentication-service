// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::UserRegistrationToken;
use mas_storage::{Clock, user::UserRegistrationTokenRepository};
use rand::RngCore;
use sqlx::{PgConnection, types::Uuid};
use ulid::Ulid;

use crate::{DatabaseInconsistencyError, errors::DatabaseError, tracing::ExecuteExt};

/// An implementation of [`mas_storage::user::UserRegistrationTokenRepository`]
/// for a PostgreSQL connection
pub struct PgUserRegistrationTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserRegistrationTokenRepository<'c> {
    /// Create a new [`PgUserRegistrationTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct UserRegistrationTokenLookup {
    user_registration_token_id: Uuid,
    token: String,
    usage_limit: Option<i32>,
    times_used: i32,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<UserRegistrationTokenLookup> for UserRegistrationToken {
    type Error = DatabaseInconsistencyError;

    fn try_from(res: UserRegistrationTokenLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(res.user_registration_token_id);

        let usage_limit = res
            .usage_limit
            .map(u32::try_from)
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("user_registration_tokens")
                    .column("usage_limit")
                    .row(id)
                    .source(e)
            })?;

        let times_used = res.times_used.try_into().map_err(|e| {
            DatabaseInconsistencyError::on("user_registration_tokens")
                .column("times_used")
                .row(id)
                .source(e)
        })?;

        Ok(UserRegistrationToken {
            id,
            token: res.token,
            usage_limit,
            times_used,
            created_at: res.created_at,
            last_used_at: res.last_used_at,
            expires_at: res.expires_at,
            revoked_at: res.revoked_at,
        })
    }
}

#[async_trait]
impl UserRegistrationTokenRepository for PgUserRegistrationTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_registration_token.lookup",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserRegistrationToken>, Self::Error> {
        let res = sqlx::query_as!(
            UserRegistrationTokenLookup,
            r#"
                SELECT user_registration_token_id,
                       token,
                       usage_limit,
                       times_used,
                       created_at,
                       last_used_at,
                       expires_at,
                       revoked_at
                FROM user_registration_tokens
                WHERE user_registration_token_id = $1
            "#,
            Uuid::from(id)
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else {
            return Ok(None);
        };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_registration_token.find_by_token",
        skip_all,
        fields(
            db.query.text,
            token = %token,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        token: &str,
    ) -> Result<Option<UserRegistrationToken>, Self::Error> {
        let res = sqlx::query_as!(
            UserRegistrationTokenLookup,
            r#"
                SELECT user_registration_token_id,
                       token,
                       usage_limit,
                       times_used,
                       created_at,
                       last_used_at,
                       expires_at,
                       revoked_at
                FROM user_registration_tokens
                WHERE token = $1
            "#,
            token
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else {
            return Ok(None);
        };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_registration_token.add",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.token = %token,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn mas_storage::Clock,
        token: String,
        usage_limit: Option<u32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);

        let usage_limit_i32 = usage_limit
            .map(i32::try_from)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        sqlx::query!(
            r#"
                INSERT INTO user_registration_tokens
                    (user_registration_token_id, token, usage_limit, created_at, expires_at)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            &token,
            usage_limit_i32,
            created_at,
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserRegistrationToken {
            id,
            token,
            usage_limit,
            times_used: 0,
            created_at,
            last_used_at: None,
            expires_at,
            revoked_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_registration_token.use_token",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn use_token(
        &mut self,
        clock: &dyn Clock,
        token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let now = clock.now();
        let new_times_used = sqlx::query_scalar!(
            r#"
                UPDATE user_registration_tokens
                SET times_used = times_used + 1,
                    last_used_at = $2
                WHERE user_registration_token_id = $1 AND revoked_at IS NULL
                RETURNING times_used
            "#,
            Uuid::from(token.id),
            now,
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await?;

        let new_times_used = new_times_used
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(UserRegistrationToken {
            times_used: new_times_used,
            last_used_at: Some(now),
            ..token
        })
    }

    #[tracing::instrument(
        name = "db.user_registration_token.revoke",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        mut token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let revoked_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE user_registration_tokens
                SET revoked_at = $2
                WHERE user_registration_token_id = $1
            "#,
            Uuid::from(token.id),
            revoked_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        token.revoked_at = Some(revoked_at);

        Ok(token)
    }
}
