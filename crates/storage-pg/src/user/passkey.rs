// Copyright 2025, 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{BrowserSession, Clock, User, UserPasskey, UserPasskeyChallenge};
use mas_storage::{
    Page, Pagination,
    pagination::Node,
    user::{UserPasskeyFilter, UserPasskeyRepository},
};
use rand::RngCore;
use sea_query::{Expr, PostgresQueryBuilder, Query, enum_def};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;
use webauthn_rp::response::{AuthTransports, CredentialId};

use crate::{
    DatabaseError, DatabaseInconsistencyError,
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
    name: Option<String>,
    transports: serde_json::Value,
    static_state: Vec<u8>,
    dynamic_state: Vec<u8>,
    metadata: Vec<u8>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl Node<Ulid> for UserPasskeyLookup {
    fn cursor(&self) -> Ulid {
        self.user_passkey_id.into()
    }
}

impl TryFrom<UserPasskeyLookup> for UserPasskey {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: UserPasskeyLookup) -> Result<UserPasskey, Self::Error> {
        Ok(UserPasskey {
            id: value.user_passkey_id.into(),
            user_id: value.user_id.into(),
            credential_id: serde_json::from_str(&value.credential_id).map_err(|e| {
                DatabaseInconsistencyError::on("user_passkeys")
                    .column("credential_id")
                    .row(value.user_passkey_id.into())
                    .source(e)
            })?,
            name: value.name,
            transports: serde_json::from_value(value.transports).map_err(|e| {
                DatabaseInconsistencyError::on("user_passkeys")
                    .column("transports")
                    .row(value.user_passkey_id.into())
                    .source(e)
            })?,
            static_state: value.static_state,
            dynamic_state: value.dynamic_state,
            metadata: value.metadata,
            last_used_at: value.last_used_at,
            created_at: value.created_at,
        })
    }
}

struct UserPasskeyChallengeLookup {
    user_passkey_challenge_id: Uuid,
    user_session_id: Option<Uuid>,
    state: Vec<u8>,
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
                     , transports
                     , static_state
                     , dynamic_state
                     , metadata
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

        Ok(Some(user_passkey.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_passkey.find",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn find(
        &mut self,
        credential_id: &CredentialId<Vec<u8>>,
    ) -> Result<Option<UserPasskey>, Self::Error> {
        let res = sqlx::query_as!(
            UserPasskeyLookup,
            r#"
                SELECT user_passkey_id
                     , user_id
                     , credential_id
                     , name
                     , transports
                     , static_state
                     , dynamic_state
                     , metadata
                     , last_used_at
                     , created_at
                FROM user_passkeys

                WHERE credential_id = $1
            "#,
            serde_json::to_string(&credential_id).map_err(DatabaseError::to_invalid_operation)?,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(user_passkey) = res else {
            return Ok(None);
        };

        Ok(Some(user_passkey.try_into()?))
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
                     , transports
                     , static_state
                     , dynamic_state
                     , metadata
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

        Ok(res
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?)
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
                Expr::col((UserPasskeys::Table, UserPasskeys::Transports)),
                UserPasskeyLookupIden::Transports,
            )
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::StaticState)),
                UserPasskeyLookupIden::StaticState,
            )
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::DynamicState)),
                UserPasskeyLookupIden::DynamicState,
            )
            .expr_as(
                Expr::col((UserPasskeys::Table, UserPasskeys::Metadata)),
                UserPasskeyLookupIden::Metadata,
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

        let page = pagination.process(edges).try_map(TryFrom::try_from)?;

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
        name: Option<String>,
        credential_id: CredentialId<Vec<u8>>,
        transports: AuthTransports,
        static_state: Vec<u8>,
        dynamic_state: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<UserPasskey, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_passkey.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_passkeys (user_passkey_id, user_id, credential_id, name, transports, static_state, dynamic_state, metadata, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            serde_json::to_string(&credential_id).map_err(DatabaseError::to_invalid_operation)?,
            name.as_deref(),
            serde_json::to_value(transports).map_err(DatabaseError::to_invalid_operation)?,
            static_state,
            dynamic_state,
            metadata,
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
            transports,
            static_state,
            dynamic_state,
            metadata,
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
            name.as_str(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_passkey.name = Some(name);
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
        dynamic_state: Vec<u8>,
    ) -> Result<UserPasskey, Self::Error> {
        let last_used_at = clock.now();

        let res = sqlx::query!(
            r#"
                UPDATE user_passkeys
                SET last_used_at = $2, dynamic_state = $3
                WHERE user_passkey_id = $1
            "#,
            Uuid::from(user_passkey.id),
            last_used_at,
            dynamic_state
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_passkey.last_used_at = Some(last_used_at);
        user_passkey.dynamic_state = dynamic_state;
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
        state: Vec<u8>,
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
        state: Vec<u8>,
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

    #[tracing::instrument(
        name = "db.user_passkey.cleanup_challenges",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn cleanup_challenges(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error> {
        // Cleanup challenges that were created more than an hour ago
        let threshold = clock.now() - Duration::microseconds(60 * 60 * 1000 * 1000);
        let res = sqlx::query!(
            r#"
                DELETE FROM user_passkey_challenges
                WHERE created_at < $1
            "#,
            threshold,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(res.rows_affected().try_into().unwrap_or(usize::MAX))
    }
}
