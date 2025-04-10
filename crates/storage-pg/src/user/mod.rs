// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! A module containing the PostgreSQL implementation of the user-related
//! repositories

use async_trait::async_trait;
use mas_data_model::User;
use mas_storage::{
    Clock,
    user::{UserFilter, UserRepository},
};
use rand::RngCore;
use sea_query::{Expr, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError,
    filter::{Filter, StatementExt},
    iden::Users,
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

mod email;
mod password;
mod recovery;
mod registration;
mod session;
mod terms;

#[cfg(test)]
mod tests;

pub use self::{
    email::PgUserEmailRepository, password::PgUserPasswordRepository,
    recovery::PgUserRecoveryRepository, registration::PgUserRegistrationRepository,
    session::PgBrowserSessionRepository, terms::PgUserTermsRepository,
};

/// An implementation of [`UserRepository`] for a PostgreSQL connection
pub struct PgUserRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserRepository<'c> {
    /// Create a new [`PgUserRepository`] from an active PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

mod priv_ {
    // The enum_def macro generates a public enum, which we don't want, because it
    // triggers the missing docs warning
    #![allow(missing_docs)]

    use chrono::{DateTime, Utc};
    use sea_query::enum_def;
    use uuid::Uuid;

    #[derive(Debug, Clone, sqlx::FromRow)]
    #[enum_def]
    pub(super) struct UserLookup {
        pub(super) user_id: Uuid,
        pub(super) username: String,
        pub(super) created_at: DateTime<Utc>,
        pub(super) locked_at: Option<DateTime<Utc>>,
        pub(super) deactivated_at: Option<DateTime<Utc>>,
        pub(super) can_request_admin: bool,
    }
}

use priv_::{UserLookup, UserLookupIden};

impl From<UserLookup> for User {
    fn from(value: UserLookup) -> Self {
        let id = value.user_id.into();
        Self {
            id,
            username: value.username,
            sub: id.to_string(),
            created_at: value.created_at,
            locked_at: value.locked_at,
            deactivated_at: value.deactivated_at,
            can_request_admin: value.can_request_admin,
        }
    }
}

impl Filter for UserFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.state().map(|state| {
                match state {
                    mas_storage::user::UserState::Deactivated => {
                        Expr::col((Users::Table, Users::DeactivatedAt)).is_not_null()
                    }
                    mas_storage::user::UserState::Locked => {
                        Expr::col((Users::Table, Users::LockedAt)).is_not_null()
                    }
                    mas_storage::user::UserState::Active => {
                        Expr::col((Users::Table, Users::LockedAt))
                            .is_null()
                            .and(Expr::col((Users::Table, Users::DeactivatedAt)).is_null())
                    }
                }
            }))
            .add_option(self.can_request_admin().map(|can_request_admin| {
                Expr::col((Users::Table, Users::CanRequestAdmin)).eq(can_request_admin)
            }))
    }
}

#[async_trait]
impl UserRepository for PgUserRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user.lookup",
        skip_all,
        fields(
            db.query.text,
            user.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error> {
        let res = sqlx::query_as!(
            UserLookup,
            r#"
                SELECT user_id
                     , username
                     , created_at
                     , locked_at
                     , deactivated_at
                     , can_request_admin
                FROM users
                WHERE user_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.user.find_by_username",
        skip_all,
        fields(
            db.query.text,
            user.username = username,
        ),
        err,
    )]
    async fn find_by_username(&mut self, username: &str) -> Result<Option<User>, Self::Error> {
        let res = sqlx::query_as!(
            UserLookup,
            r#"
                SELECT user_id
                     , username
                     , created_at
                     , locked_at
                     , deactivated_at
                     , can_request_admin
                FROM users
                WHERE LOWER(username) = LOWER($1)
            "#,
            username,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.user.add",
        skip_all,
        fields(
            db.query.text,
            user.username = username,
            user.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
    ) -> Result<User, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user.id", tracing::field::display(id));

        let res = sqlx::query!(
            r#"
                INSERT INTO users (user_id, username, created_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (username) DO NOTHING
            "#,
            Uuid::from(id),
            username,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        // If the user already exists, want to return an error but not poison the
        // transaction
        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(User {
            id,
            username,
            sub: id.to_string(),
            created_at,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
        })
    }

    #[tracing::instrument(
        name = "db.user.exists",
        skip_all,
        fields(
            db.query.text,
            user.username = username,
        ),
        err,
    )]
    async fn exists(&mut self, username: &str) -> Result<bool, Self::Error> {
        let exists = sqlx::query_scalar!(
            r#"
                SELECT EXISTS(
                    SELECT 1 FROM users WHERE LOWER(username) = LOWER($1)
                ) AS "exists!"
            "#,
            username
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await?;

        Ok(exists)
    }

    #[tracing::instrument(
        name = "db.user.lock",
        skip_all,
        fields(
            db.query.text,
            %user.id,
        ),
        err,
    )]
    async fn lock(&mut self, clock: &dyn Clock, mut user: User) -> Result<User, Self::Error> {
        if user.locked_at.is_some() {
            return Ok(user);
        }

        let locked_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE users
                SET locked_at = $1
                WHERE user_id = $2
            "#,
            locked_at,
            Uuid::from(user.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user.locked_at = Some(locked_at);

        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.unlock",
        skip_all,
        fields(
            db.query.text,
            %user.id,
        ),
        err,
    )]
    async fn unlock(&mut self, mut user: User) -> Result<User, Self::Error> {
        if user.locked_at.is_none() {
            return Ok(user);
        }

        let res = sqlx::query!(
            r#"
                UPDATE users
                SET locked_at = NULL
                WHERE user_id = $1
            "#,
            Uuid::from(user.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user.locked_at = None;

        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.deactivate",
        skip_all,
        fields(
            db.query.text,
            %user.id,
        ),
        err,
    )]
    async fn deactivate(&mut self, clock: &dyn Clock, mut user: User) -> Result<User, Self::Error> {
        if user.deactivated_at.is_some() {
            return Ok(user);
        }

        let deactivated_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE users
                SET deactivated_at = $2
                WHERE user_id = $1
                  AND deactivated_at IS NULL
            "#,
            Uuid::from(user.id),
            deactivated_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user.deactivated_at = Some(user.created_at);

        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.set_can_request_admin",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            user.can_request_admin = can_request_admin,
        ),
        err,
    )]
    async fn set_can_request_admin(
        &mut self,
        mut user: User,
        can_request_admin: bool,
    ) -> Result<User, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE users
                SET can_request_admin = $2
                WHERE user_id = $1
            "#,
            Uuid::from(user.id),
            can_request_admin,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user.can_request_admin = can_request_admin;

        Ok(user)
    }

    #[tracing::instrument(
        name = "db.user.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: UserFilter<'_>,
        pagination: mas_storage::Pagination,
    ) -> Result<mas_storage::Page<User>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((Users::Table, Users::UserId)),
                UserLookupIden::UserId,
            )
            .expr_as(
                Expr::col((Users::Table, Users::Username)),
                UserLookupIden::Username,
            )
            .expr_as(
                Expr::col((Users::Table, Users::CreatedAt)),
                UserLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((Users::Table, Users::LockedAt)),
                UserLookupIden::LockedAt,
            )
            .expr_as(
                Expr::col((Users::Table, Users::DeactivatedAt)),
                UserLookupIden::DeactivatedAt,
            )
            .expr_as(
                Expr::col((Users::Table, Users::CanRequestAdmin)),
                UserLookupIden::CanRequestAdmin,
            )
            .from(Users::Table)
            .apply_filter(filter)
            .generate_pagination((Users::Table, Users::UserId), pagination)
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<UserLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).map(User::from);

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.user.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn count(&mut self, filter: UserFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(Expr::col((Users::Table, Users::UserId)).count())
            .from(Users::Table)
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
        name = "db.user.acquire_lock_for_sync",
        skip_all,
        fields(
            db.query.text,
            user.id = %user.id,
        ),
        err,
    )]
    async fn acquire_lock_for_sync(&mut self, user: &User) -> Result<(), Self::Error> {
        // XXX: this lock isn't stictly scoped to users, but as we don't use many
        // postgres advisory locks, it's fine for now. Later on, we could use row-level
        // locks to make sure we don't get into trouble

        // Convert the user ID to a u128 and grab the lower 64 bits
        // As this includes 64bit of the random part of the ULID, it should be random
        // enough to not collide
        let lock_id = (u128::from(user.id) & 0xffff_ffff_ffff_ffff) as i64;

        // Use a PG advisory lock, which will be released when the transaction is
        // committed or rolled back
        sqlx::query!(
            r#"
                SELECT pg_advisory_xact_lock($1)
            "#,
            lock_id,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }
}
