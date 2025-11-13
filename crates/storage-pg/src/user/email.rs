// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    BrowserSession, Clock, User, UserEmail, UserEmailAuthentication, UserEmailAuthenticationCode,
    UserRegistration,
};
use mas_storage::{
    Page, Pagination,
    pagination::Node,
    user::{UserEmailFilter, UserEmailRepository},
};
use rand::RngCore;
use sea_query::{Expr, Func, PostgresQueryBuilder, Query, SimpleExpr, enum_def};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError,
    filter::{Filter, StatementExt},
    iden::UserEmails,
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

/// An implementation of [`UserEmailRepository`] for a PostgreSQL connection
pub struct PgUserEmailRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserEmailRepository<'c> {
    /// Create a new [`PgUserEmailRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[enum_def]
struct UserEmailLookup {
    user_email_id: Uuid,
    user_id: Uuid,
    email: String,
    created_at: DateTime<Utc>,
}

impl Node<Ulid> for UserEmailLookup {
    fn cursor(&self) -> Ulid {
        self.user_email_id.into()
    }
}

impl From<UserEmailLookup> for UserEmail {
    fn from(e: UserEmailLookup) -> UserEmail {
        UserEmail {
            id: e.user_email_id.into(),
            user_id: e.user_id.into(),
            email: e.email,
            created_at: e.created_at,
        }
    }
}

struct UserEmailAuthenticationLookup {
    user_email_authentication_id: Uuid,
    user_session_id: Option<Uuid>,
    user_registration_id: Option<Uuid>,
    email: String,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<UserEmailAuthenticationLookup> for UserEmailAuthentication {
    fn from(value: UserEmailAuthenticationLookup) -> Self {
        UserEmailAuthentication {
            id: value.user_email_authentication_id.into(),
            user_session_id: value.user_session_id.map(Ulid::from),
            user_registration_id: value.user_registration_id.map(Ulid::from),
            email: value.email,
            created_at: value.created_at,
            completed_at: value.completed_at,
        }
    }
}

struct UserEmailAuthenticationCodeLookup {
    user_email_authentication_code_id: Uuid,
    user_email_authentication_id: Uuid,
    code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<UserEmailAuthenticationCodeLookup> for UserEmailAuthenticationCode {
    fn from(value: UserEmailAuthenticationCodeLookup) -> Self {
        UserEmailAuthenticationCode {
            id: value.user_email_authentication_code_id.into(),
            user_email_authentication_id: value.user_email_authentication_id.into(),
            code: value.code,
            created_at: value.created_at,
            expires_at: value.expires_at,
        }
    }
}

impl Filter for UserEmailFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.user().map(|user| {
                Expr::col((UserEmails::Table, UserEmails::UserId)).eq(Uuid::from(user.id))
            }))
            .add_option(self.email().map(|email| {
                SimpleExpr::from(Func::lower(Expr::col((
                    UserEmails::Table,
                    UserEmails::Email,
                ))))
                .eq(Func::lower(email))
            }))
    }
}

#[async_trait]
impl UserEmailRepository for PgUserEmailRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_email.lookup",
        skip_all,
        fields(
            db.query.text,
            user_email.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserEmail>, Self::Error> {
        let res = sqlx::query_as!(
            UserEmailLookup,
            r#"
                SELECT user_email_id
                     , user_id
                     , email
                     , created_at
                FROM user_emails

                WHERE user_email_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(user_email) = res else {
            return Ok(None);
        };

        Ok(Some(user_email.into()))
    }

    #[tracing::instrument(
        name = "db.user_email.find",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            user_email.email = email,
        ),
        err,
    )]
    async fn find(&mut self, user: &User, email: &str) -> Result<Option<UserEmail>, Self::Error> {
        let res = sqlx::query_as!(
            UserEmailLookup,
            r#"
                SELECT user_email_id
                     , user_id
                     , email
                     , created_at
                FROM user_emails

                WHERE user_id = $1 AND LOWER(email) = LOWER($2)
            "#,
            Uuid::from(user.id),
            email,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(user_email) = res else {
            return Ok(None);
        };

        Ok(Some(user_email.into()))
    }

    #[tracing::instrument(
        name = "db.user_email.find_by_email",
        skip_all,
        fields(
            db.query.text,
            user_email.email = email,
        ),
        err,
    )]
    async fn find_by_email(&mut self, email: &str) -> Result<Option<UserEmail>, Self::Error> {
        let res = sqlx::query_as!(
            UserEmailLookup,
            r#"
                SELECT user_email_id
                     , user_id
                     , email
                     , created_at
                FROM user_emails
                WHERE LOWER(email) = LOWER($1)
            "#,
            email,
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        if res.len() != 1 {
            return Ok(None);
        }

        let Some(user_email) = res.into_iter().next() else {
            return Ok(None);
        };

        Ok(Some(user_email.into()))
    }

    #[tracing::instrument(
        name = "db.user_email.all",
        skip_all,
        fields(
            db.query.text,
            %user.id,
        ),
        err,
    )]
    async fn all(&mut self, user: &User) -> Result<Vec<UserEmail>, Self::Error> {
        let res = sqlx::query_as!(
            UserEmailLookup,
            r#"
                SELECT user_email_id
                     , user_id
                     , email
                     , created_at
                FROM user_emails

                WHERE user_id = $1

                ORDER BY email ASC
            "#,
            Uuid::from(user.id),
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        Ok(res.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(
        name = "db.user_email.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: UserEmailFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserEmail>, DatabaseError> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((UserEmails::Table, UserEmails::UserEmailId)),
                UserEmailLookupIden::UserEmailId,
            )
            .expr_as(
                Expr::col((UserEmails::Table, UserEmails::UserId)),
                UserEmailLookupIden::UserId,
            )
            .expr_as(
                Expr::col((UserEmails::Table, UserEmails::Email)),
                UserEmailLookupIden::Email,
            )
            .expr_as(
                Expr::col((UserEmails::Table, UserEmails::CreatedAt)),
                UserEmailLookupIden::CreatedAt,
            )
            .from(UserEmails::Table)
            .apply_filter(filter)
            .generate_pagination((UserEmails::Table, UserEmails::UserEmailId), pagination)
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<UserEmailLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).map(UserEmail::from);

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.user_email.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn count(&mut self, filter: UserEmailFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(Expr::col((UserEmails::Table, UserEmails::UserEmailId)).count())
            .from(UserEmails::Table)
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
        name = "db.user_email.add",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            user_email.id,
            user_email.email = email,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        email: String,
    ) -> Result<UserEmail, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_email.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_emails (user_email_id, user_id, email, created_at)
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            &email,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserEmail {
            id,
            user_id: user.id,
            email,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_email.remove",
        skip_all,
        fields(
            db.query.text,
            user.id = %user_email.user_id,
            %user_email.id,
            %user_email.email,
        ),
        err,
    )]
    async fn remove(&mut self, user_email: UserEmail) -> Result<(), Self::Error> {
        let res = sqlx::query!(
            r#"
                DELETE FROM user_emails
                WHERE user_email_id = $1
            "#,
            Uuid::from(user_email.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.user_email.remove_bulk",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn remove_bulk(&mut self, filter: UserEmailFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::delete()
            .from_table(UserEmails::Table)
            .apply_filter(filter)
            .build_sqlx(PostgresQueryBuilder);

        let res = sqlx::query_with(&sql, arguments)
            .traced()
            .execute(&mut *self.conn)
            .await?;

        Ok(res.rows_affected().try_into().unwrap_or(usize::MAX))
    }

    #[tracing::instrument(
        name = "db.user_email.add_authentication_for_session",
        skip_all,
        fields(
            db.query.text,
            %session.id,
            user_email_authentication.id,
            user_email_authentication.email = email,
        ),
        err,
    )]
    async fn add_authentication_for_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        session: &BrowserSession,
    ) -> Result<UserEmailAuthentication, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current()
            .record("user_email_authentication.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_email_authentications
                  ( user_email_authentication_id
                  , user_session_id
                  , email
                  , created_at
                  )
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(session.id),
            &email,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserEmailAuthentication {
            id,
            user_session_id: Some(session.id),
            user_registration_id: None,
            email,
            created_at,
            completed_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_email.add_authentication_for_registration",
        skip_all,
        fields(
            db.query.text,
            %user_registration.id,
            user_email_authentication.id,
            user_email_authentication.email = email,
        ),
        err,
    )]
    async fn add_authentication_for_registration(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        user_registration: &UserRegistration,
    ) -> Result<UserEmailAuthentication, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current()
            .record("user_email_authentication.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_email_authentications
                  ( user_email_authentication_id
                  , user_registration_id
                  , email
                  , created_at
                  )
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(user_registration.id),
            &email,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserEmailAuthentication {
            id,
            user_session_id: None,
            user_registration_id: Some(user_registration.id),
            email,
            created_at,
            completed_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_email.add_authentication_code",
        skip_all,
        fields(
            db.query.text,
            %user_email_authentication.id,
            %user_email_authentication.email,
            user_email_authentication_code.id,
            user_email_authentication_code.code = code,
        ),
        err,
    )]
    async fn add_authentication_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        duration: chrono::Duration,
        user_email_authentication: &UserEmailAuthentication,
        code: String,
    ) -> Result<UserEmailAuthenticationCode, Self::Error> {
        let created_at = clock.now();
        let expires_at = created_at + duration;
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record(
            "user_email_authentication_code.id",
            tracing::field::display(id),
        );

        sqlx::query!(
            r#"
                INSERT INTO user_email_authentication_codes
                  ( user_email_authentication_code_id
                  , user_email_authentication_id
                  , code
                  , created_at
                  , expires_at
                  )
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(user_email_authentication.id),
            &code,
            created_at,
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserEmailAuthenticationCode {
            id,
            user_email_authentication_id: user_email_authentication.id,
            code,
            created_at,
            expires_at,
        })
    }

    #[tracing::instrument(
        name = "db.user_email.lookup_authentication",
        skip_all,
        fields(
            db.query.text,
            user_email_authentication.id = %id,
        ),
        err,
    )]
    async fn lookup_authentication(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserEmailAuthentication>, Self::Error> {
        let res = sqlx::query_as!(
            UserEmailAuthenticationLookup,
            r#"
                SELECT user_email_authentication_id
                     , user_session_id
                     , user_registration_id
                     , email
                     , created_at
                     , completed_at
                FROM user_email_authentications
                WHERE user_email_authentication_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        Ok(res.map(UserEmailAuthentication::from))
    }

    #[tracing::instrument(
        name = "db.user_email.find_authentication_by_code",
        skip_all,
        fields(
            db.query.text,
            %authentication.id,
            user_email_authentication_code.code = code,
        ),
        err,
    )]
    async fn find_authentication_code(
        &mut self,
        authentication: &UserEmailAuthentication,
        code: &str,
    ) -> Result<Option<UserEmailAuthenticationCode>, Self::Error> {
        let res = sqlx::query_as!(
            UserEmailAuthenticationCodeLookup,
            r#"
                SELECT user_email_authentication_code_id
                     , user_email_authentication_id
                     , code
                     , created_at
                     , expires_at
                FROM user_email_authentication_codes
                WHERE user_email_authentication_id = $1
                  AND code = $2
            "#,
            Uuid::from(authentication.id),
            code,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        Ok(res.map(UserEmailAuthenticationCode::from))
    }

    #[tracing::instrument(
        name = "db.user_email.complete_email_authentication",
        skip_all,
        fields(
            db.query.text,
            %user_email_authentication.id,
            %user_email_authentication.email,
            %user_email_authentication_code.id,
            %user_email_authentication_code.code,
        ),
        err,
    )]
    async fn complete_authentication(
        &mut self,
        clock: &dyn Clock,
        mut user_email_authentication: UserEmailAuthentication,
        user_email_authentication_code: &UserEmailAuthenticationCode,
    ) -> Result<UserEmailAuthentication, Self::Error> {
        // We technically don't use the authentication code here (other than
        // recording it in the span), but this is to make sure the caller has
        // fetched one before calling this
        let completed_at = clock.now();

        // We'll assume the caller has checked that completed_at is None, so in case
        // they haven't, the update will not affect any rows, which will raise
        // an error
        let res = sqlx::query!(
            r#"
                UPDATE user_email_authentications
                SET completed_at = $2
                WHERE user_email_authentication_id = $1
                  AND completed_at IS NULL
            "#,
            Uuid::from(user_email_authentication.id),
            completed_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        user_email_authentication.completed_at = Some(completed_at);
        Ok(user_email_authentication)
    }
}
