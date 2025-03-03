// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{BrowserSession, User, UserPasskey, UserPasskeyChallenge};
use mas_storage::{
    Clock, Page, Pagination,
    user::{UserPasskeyFilter, UserPasskeyRepository},
};
use rand::RngCore;
use sea_query::{Expr, PostgresQueryBuilder, Query, enum_def};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError,
    filter::{Filter, StatementExt},
    iden::UserPasskeys,
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

/// An implementation of [`UserPasskeyRepository`] for a PostgreSQL connection
pub struct PgUserPasskeyRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserPasskeyRepository<'c> {
    /// Create a new [`PgUserPasskeyRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[enum_def]
struct UserPasskeyLookup {
    user_passkey_id: Uuid,
    user_id: Uuid,
    credential_id: String,
    name: String,
    data: serde_json::Value,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<UserPasskeyLookup> for UserPasskey {
    fn from(value: UserPasskeyLookup) -> UserPasskey {
        UserPasskey {
            id: value.user_passkey_id.into(),
            user_id: value.user_id.into(),
            credential_id: value.credential_id,
            name: value.name,
            data: value.data,
            last_used_at: value.last_used_at,
            created_at: value.created_at,
        }
    }
}

struct UserPasskeyChallengeLookup {
    user_passkey_challenge_id: Uuid,
    user_session_id: Option<Uuid>,
    state: serde_json::Value,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<UserPasskeyChallengeLookup> for UserPasskeyChallenge {
    fn from(value: UserPasskeyChallengeLookup) -> Self {
        UserPasskeyChallenge {
            id: value.user_passkey_challenge_id.into(),
            user_session_id: value.user_session_id.map(Ulid::from),
            state: value.state,
            created_at: value.created_at,
            completed_at: value.completed_at,
        }
    }
}

impl Filter for UserPasskeyFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all().add_option(self.user().map(|user| {
            Expr::col((UserPasskeys::Table, UserPasskeys::UserId)).eq(Uuid::from(user.id))
        }))
    }
}

#[async_trait]
impl UserPasskeyRepository for PgUserPasskeyRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_passkey.lookup",
        skip_all,
        fields(
            db.query.text,
            user_passkey.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserPasskey>, Self::Error> {
        let res = sqlx::query_as!(
            UserPasskeyLookup,
            r#"
                SELECT user_passkey_id
                     , user_id
                     , credential_id
                     , name
                     , data
                     , last_used_at
                     , created_at
                FROM user_passkeys

                WHERE user_passkey_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(user_passkey) = res else {
            return Ok(None);
        };

        Ok(Some(user_passkey.into()))
    }

    #[tracing::instrument(
        name = "db.user_passkey.find",
        skip_all,
        fields(
            db.query.text,
            %credential_id,
        ),
        err,
    )]
    async fn find(&mut self, credential_id: &str) -> Result<Option<UserPasskey>, Self::Error> {
        let res = sqlx::query_as!(
            UserPasskeyLookup,
            r#"
                SELECT user_passkey_id
                     , user_id
                     , credential_id
                     , name
                     , data
                     , last_used_at
                     , created_at
                FROM user_passkeys

                WHERE credential_id = $1
            "#,
            credential_id
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(user_passkey) = res else {
            return Ok(None);
        };

        Ok(Some(user_passkey.into()))
    }

    #[tracing::instrument(
        name = "db.user_passkey.all",
        skip_all,
        fields(
            db.query.text,
            %user.id,
        ),
        err,
    )]
    async fn all(&mut self, user: &User) -> Result<Vec<UserPasskey>, Self::Error> {
        let res = sqlx::query_as!(
            UserPasskeyLookup,
            r#"
                SELECT user_passkey_id
                     , user_id
                     , credential_id
                     , name
                     , data
                     , last_used_at
                     , created_at
                FROM user_passkeys

                WHERE user_id = $1

                ORDER BY created_at ASC
            "#,
            Uuid::from(user.id),
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        Ok(res.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(
        name = "db.user_passkey.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: UserPasskeyFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserPasskey>, DatabaseError> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::UserPasskeyId)),
                UserPasskeyLookupIden::UserPasskeyId,
            )
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::UserId)),
                UserPasskeyLookupIden::UserId,
            )
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::CredentialId)),
                UserPasskeyLookupIden::CredentialId,
            )
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::Name)),
                UserPasskeyLookupIden::Name,
            )
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::Data)),
                UserPasskeyLookupIden::Data,
            )
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::LastUsedAt)),
                UserPasskeyLookupIden::LastUsedAt,
            )
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::CreatedAt)),
                UserPasskeyLookupIden::CreatedAt,
            )
            .from(UserPasskeys::Table)
            .apply_filter(filter)
            .generate_pagination(
                (UserPasskeys::Table, UserPasskeys::UserPasskeyId),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<UserPasskeyLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).map(UserPasskey::from);

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.user_passkey.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn count(&mut self, filter: UserPasskeyFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(Expr::col((UserPasskeys::Table, UserPasskeys::UserPasskeyId)).count())
            .from(UserPasskeys::Table)
            .apply_filter(filter)
            .build_sqlx(PostgresQueryBuilder);

        let count: i64 = sqlx::query_scalar_with(&sql, arguments)
            .traced()
            .fetch_one(&mut *self.conn)
            .await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.user_passkey.add",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            user_passkey.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        credential_id: String,
        name: String,
        data: serde_json::Value,
    ) -> Result<UserPasskey, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_passkey.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_passkeys (user_passkey_id, user_id, credential_id, name, data, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            &credential_id,
            &name,
            data,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserPasskey {
            id,
            user_id: user.id,
            credential_id,
            name,
            data,
            last_used_at: None,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_passkey.rename",
        skip_all,
        fields(
            db.query.text,
            %user_passkey.id,
        ),
        err,
    )]
    async fn rename(
        &mut self,
        mut user_passkey: UserPasskey,
        name: String,
    ) -> Result<UserPasskey, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE user_passkeys
                SET name = $2
                WHERE user_passkey_id = $1
            "#,
            Uuid::from(user_passkey.id),
            name,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_passkey.name = name;
        Ok(user_passkey)
    }

    #[tracing::instrument(
        name = "db.user_passkey.update",
        skip_all,
        fields(
            db.query.text,
            %user_passkey.id,
        ),
        err,
    )]
    async fn update(
        &mut self,
        clock: &dyn Clock,
        mut user_passkey: UserPasskey,
        data: serde_json::Value,
    ) -> Result<UserPasskey, Self::Error> {
        let last_used_at = clock.now();

        let res = sqlx::query!(
            r#"
                UPDATE user_passkeys
                SET last_used_at = $2, data = $3
                WHERE user_passkey_id = $1
            "#,
            Uuid::from(user_passkey.id),
            last_used_at,
            data
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_passkey.last_used_at = Some(last_used_at);
        user_passkey.data = data;
        Ok(user_passkey)
    }

    #[tracing::instrument(
        name = "db.user_passkey.remove",
        skip_all,
        fields(
            db.query.text,
            user.id = %user_passkey.user_id,
            %user_passkey.id,
        ),
        err,
    )]
    async fn remove(&mut self, user_passkey: UserPasskey) -> Result<(), Self::Error> {
        let res = sqlx::query!(
            r#"
                DELETE FROM user_passkeys
                WHERE user_passkey_id = $1
            "#,
            Uuid::from(user_passkey.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.user_passkey.add_challenge_for_session",
        skip_all,
        fields(
            db.query.text,
            %session.id,
            user_passkey_challenge.id,
        ),
        err,
    )]
    async fn add_challenge_for_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        state: serde_json::Value,
        session: &BrowserSession,
    ) -> Result<UserPasskeyChallenge, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_passkey_challenge.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_passkey_challenges
                  ( user_passkey_challenge_id
                  , user_session_id
                  , state
                  , created_at
                  )
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(session.id),
            state,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserPasskeyChallenge {
            id,
            user_session_id: Some(session.id),
            state,
            created_at,
            completed_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_passkey.add_challenge",
        skip_all,
        fields(
            db.query.text,
            user_passkey_challenge.id,
        ),
        err,
    )]
    async fn add_challenge(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        state: serde_json::Value,
    ) -> Result<UserPasskeyChallenge, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_passkey_challenge.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_passkey_challenges
                  ( user_passkey_challenge_id
                  , state
                  , created_at
                  )
                VALUES ($1, $2, $3)
            "#,
            Uuid::from(id),
            state,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserPasskeyChallenge {
            id,
            user_session_id: None,
            state,
            created_at,
            completed_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_passkey.lookup_challenge",
        skip_all,
        fields(
            db.query.text,
            user_passkey_challenge.id = %id,
        ),
        err,
    )]
    async fn lookup_challenge(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserPasskeyChallenge>, Self::Error> {
        let res = sqlx::query_as!(
            UserPasskeyChallengeLookup,
            r#"
                SELECT user_passkey_challenge_id
                     , user_session_id
                     , state
                     , created_at
                     , completed_at
                FROM user_passkey_challenges
                WHERE user_passkey_challenge_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        Ok(res.map(UserPasskeyChallenge::from))
    }

    #[tracing::instrument(
        name = "db.user_passkey.complete_challenge",
        skip_all,
        fields(
            db.query.text,
            %user_passkey_challenge.id,
        ),
        err,
    )]
    async fn complete_challenge(
        &mut self,
        clock: &dyn Clock,
        mut user_passkey_challenge: UserPasskeyChallenge,
    ) -> Result<UserPasskeyChallenge, Self::Error> {
        let completed_at = clock.now();

        let res = sqlx::query!(
            r#"
                UPDATE user_passkey_challenges
                SET completed_at = $2
                WHERE user_passkey_challenge_id = $1
                  AND completed_at IS NULL
            "#,
            Uuid::from(user_passkey_challenge.id),
            completed_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_passkey_challenge.completed_at = Some(completed_at);
        Ok(user_passkey_challenge)
    }
}
