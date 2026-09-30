// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::num::NonZeroU64;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{Clock, UlidExt as _, User, UserSessionLimitOverride};
use mas_storage::{
    Page, Pagination,
    pagination::Node,
    user::{UserSessionLimitOverrideFilter, UserSessionLimitOverrideRepository},
};
use rand::RngCore;
use sea_query::{Expr, ExprTrait, PostgresQueryBuilder, Query, enum_def};
use sea_query_sqlx::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    filter::{Filter, StatementExt},
    iden::UserSessionLimitOverrides,
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

/// An implementation of [`UserSessionLimitOverrideRepository`] for PostgreSQL
pub struct PgUserSessionLimitOverrideRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserSessionLimitOverrideRepository<'c> {
    /// Create a new [`PgUserSessionLimitOverrideRepository`]
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[enum_def]
struct UserSessionLimitOverrideLookup {
    user_session_limit_override_id: Uuid,
    user_id: Uuid,
    oauth2_client_id: Option<Uuid>,
    soft_limit: i64,
    hard_limit: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Node<Ulid> for UserSessionLimitOverrideLookup {
    fn cursor(&self) -> Ulid {
        self.user_session_limit_override_id.into()
    }
}

impl TryFrom<UserSessionLimitOverrideLookup> for UserSessionLimitOverride {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: UserSessionLimitOverrideLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.user_session_limit_override_id);
        let soft_limit = u64::try_from(value.soft_limit)
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or_else(|| {
                DatabaseInconsistencyError::on("user_session_limit_overrides")
                    .column("soft_limit")
                    .row(id)
            })?;
        let hard_limit = u64::try_from(value.hard_limit)
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or_else(|| {
                DatabaseInconsistencyError::on("user_session_limit_overrides")
                    .column("hard_limit")
                    .row(id)
            })?;

        Ok(Self {
            id,
            user_id: value.user_id.into(),
            oauth2_client_id: value.oauth2_client_id.map(Ulid::from),
            soft_limit,
            hard_limit,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

impl Filter for UserSessionLimitOverrideFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.user().map(|user| {
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::UserId,
                ))
                .eq(Uuid::from(user.id))
            }))
            .add_option(self.client().map(|client| {
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::OAuth2ClientId,
                ))
                .eq(Uuid::from(client.id))
            }))
            .add_option(self.is_global_only().then(|| {
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::OAuth2ClientId,
                ))
                .is_null()
            }))
    }
}

#[async_trait]
impl UserSessionLimitOverrideRepository for PgUserSessionLimitOverrideRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_session_limit_override.lookup",
        skip_all,
        fields(db.query.text, user_session_limit_override.id = %id),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserSessionLimitOverride>, Self::Error> {
        let res = sqlx::query_as!(
            UserSessionLimitOverrideLookup,
            r#"
                SELECT user_session_limit_override_id
                     , user_id
                     , oauth2_client_id
                     , soft_limit
                     , hard_limit
                     , created_at
                     , updated_at
                FROM user_session_limit_overrides
                WHERE user_session_limit_override_id = $1
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
        name = "db.user_session_limit_override.find",
        skip_all,
        fields(db.query.text, %user.id, ?client_id),
        err,
    )]
    async fn find(
        &mut self,
        user: &User,
        client_id: Option<Ulid>,
    ) -> Result<Option<UserSessionLimitOverride>, Self::Error> {
        let res = sqlx::query_as!(
            UserSessionLimitOverrideLookup,
            r#"
                SELECT user_session_limit_override_id
                     , user_id
                     , oauth2_client_id
                     , soft_limit
                     , hard_limit
                     , created_at
                     , updated_at
                FROM user_session_limit_overrides
                WHERE user_id = $1
                  AND oauth2_client_id IS NOT DISTINCT FROM $2
            "#,
            Uuid::from(user.id),
            client_id.map(Uuid::from),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };
        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_session_limit_override.list",
        skip_all,
        fields(db.query.text),
        err,
    )]
    async fn list(
        &mut self,
        filter: UserSessionLimitOverrideFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserSessionLimitOverride>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::UserSessionLimitOverrideId,
                )),
                UserSessionLimitOverrideLookupIden::UserSessionLimitOverrideId,
            )
            .expr_as(
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::UserId,
                )),
                UserSessionLimitOverrideLookupIden::UserId,
            )
            .expr_as(
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::OAuth2ClientId,
                )),
                UserSessionLimitOverrideLookupIden::Oauth2ClientId,
            )
            .expr_as(
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::SoftLimit,
                )),
                UserSessionLimitOverrideLookupIden::SoftLimit,
            )
            .expr_as(
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::HardLimit,
                )),
                UserSessionLimitOverrideLookupIden::HardLimit,
            )
            .expr_as(
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::CreatedAt,
                )),
                UserSessionLimitOverrideLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::UpdatedAt,
                )),
                UserSessionLimitOverrideLookupIden::UpdatedAt,
            )
            .from(UserSessionLimitOverrides::Table)
            .apply_filter(filter)
            .generate_pagination(
                (
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::UserSessionLimitOverrideId,
                ),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<UserSessionLimitOverrideLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination
            .process(edges)
            .try_map(UserSessionLimitOverride::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.user_session_limit_override.count",
        skip_all,
        fields(db.query.text),
        err,
    )]
    async fn count(
        &mut self,
        filter: UserSessionLimitOverrideFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(
                Expr::col((
                    UserSessionLimitOverrides::Table,
                    UserSessionLimitOverrides::UserSessionLimitOverrideId,
                ))
                .count(),
            )
            .from(UserSessionLimitOverrides::Table)
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
        name = "db.user_session_limit_override.add",
        skip_all,
        fields(db.query.text, %user.id, ?client_id),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        client_id: Option<Ulid>,
        soft_limit: NonZeroU64,
        hard_limit: NonZeroU64,
    ) -> Result<UserSessionLimitOverride, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_rng(created_at, rng);

        sqlx::query!(
            r#"
                INSERT INTO user_session_limit_overrides
                    (user_session_limit_override_id, user_id, oauth2_client_id,
                     soft_limit, hard_limit, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $6)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            client_id.map(Uuid::from),
            i64::try_from(soft_limit.get()).map_err(DatabaseError::to_invalid_operation)?,
            i64::try_from(hard_limit.get()).map_err(DatabaseError::to_invalid_operation)?,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserSessionLimitOverride {
            id,
            user_id: user.id,
            oauth2_client_id: client_id,
            soft_limit,
            hard_limit,
            created_at,
            updated_at: created_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_session_limit_override.set_limits",
        skip_all,
        fields(db.query.text, user_session_limit_override.id = %override_row.id),
        err,
    )]
    async fn set_limits(
        &mut self,
        clock: &dyn Clock,
        mut override_row: UserSessionLimitOverride,
        soft_limit: NonZeroU64,
        hard_limit: NonZeroU64,
    ) -> Result<UserSessionLimitOverride, Self::Error> {
        let updated_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE user_session_limit_overrides
                SET soft_limit = $2
                  , hard_limit = $3
                  , updated_at = $4
                WHERE user_session_limit_override_id = $1
            "#,
            Uuid::from(override_row.id),
            i64::try_from(soft_limit.get()).map_err(DatabaseError::to_invalid_operation)?,
            i64::try_from(hard_limit.get()).map_err(DatabaseError::to_invalid_operation)?,
            updated_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        override_row.soft_limit = soft_limit;
        override_row.hard_limit = hard_limit;
        override_row.updated_at = updated_at;
        Ok(override_row)
    }

    #[tracing::instrument(
        name = "db.user_session_limit_override.remove",
        skip_all,
        fields(db.query.text, user_session_limit_override.id = %override_row.id),
        err,
    )]
    async fn remove(&mut self, override_row: UserSessionLimitOverride) -> Result<(), Self::Error> {
        let res = sqlx::query!(
            r#"
                DELETE FROM user_session_limit_overrides
                WHERE user_session_limit_override_id = $1
            "#,
            Uuid::from(override_row.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)
    }
}
