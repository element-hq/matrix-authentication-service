// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{User, UserEmail, UserEmailVerification, UserEmailVerificationState};
use mas_storage::{
    user::{UserEmailFilter, UserEmailRepository},
    Clock, Page, Pagination,
};
use opentelemetry_semantic_conventions::attribute::DB_QUERY_TEXT;
use rand::RngCore;
use sea_query::{enum_def, Expr, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use tracing::{info_span, Instrument};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    filter::{Filter, StatementExt},
    iden::UserEmails,
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
    DatabaseError,
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
    confirmed_at: Option<DateTime<Utc>>,
}

impl From<UserEmailLookup> for UserEmail {
    fn from(e: UserEmailLookup) -> UserEmail {
        UserEmail {
            id: e.user_email_id.into(),
            user_id: e.user_id.into(),
            email: e.email,
            created_at: e.created_at,
            confirmed_at: e.confirmed_at,
        }
    }
}

struct UserEmailConfirmationCodeLookup {
    user_email_confirmation_code_id: Uuid,
    user_email_id: Uuid,
    code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

impl UserEmailConfirmationCodeLookup {
    fn into_verification(self, clock: &dyn Clock) -> UserEmailVerification {
        let now = clock.now();
        let state = if let Some(when) = self.consumed_at {
            UserEmailVerificationState::AlreadyUsed { when }
        } else if self.expires_at < now {
            UserEmailVerificationState::Expired {
                when: self.expires_at,
            }
        } else {
            UserEmailVerificationState::Valid
        };

        UserEmailVerification {
            id: self.user_email_confirmation_code_id.into(),
            user_email_id: self.user_email_id.into(),
            code: self.code,
            state,
            created_at: self.created_at,
        }
    }
}

impl Filter for UserEmailFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.user().map(|user| {
                Expr::col((UserEmails::Table, UserEmails::UserId)).eq(Uuid::from(user.id))
            }))
            .add_option(
                self.email()
                    .map(|email| Expr::col((UserEmails::Table, UserEmails::Email)).eq(email)),
            )
            .add_option(self.state().map(|state| {
                if state.is_verified() {
                    Expr::col((UserEmails::Table, UserEmails::ConfirmedAt)).is_not_null()
                } else {
                    Expr::col((UserEmails::Table, UserEmails::ConfirmedAt)).is_null()
                }
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
                     , confirmed_at
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
                     , confirmed_at
                FROM user_emails

                WHERE user_id = $1 AND email = $2
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
                     , confirmed_at
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
            .expr_as(
                Expr::col((UserEmails::Table, UserEmails::ConfirmedAt)),
                UserEmailLookupIden::ConfirmedAt,
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
            confirmed_at: None,
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
        let span = info_span!(
            "db.user_email.remove.codes",
            { DB_QUERY_TEXT } = tracing::field::Empty
        );
        sqlx::query!(
            r#"
                DELETE FROM user_email_confirmation_codes
                WHERE user_email_id = $1
            "#,
            Uuid::from(user_email.id),
        )
        .record(&span)
        .execute(&mut *self.conn)
        .instrument(span)
        .await?;

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

    async fn mark_as_verified(
        &mut self,
        clock: &dyn Clock,
        mut user_email: UserEmail,
    ) -> Result<UserEmail, Self::Error> {
        let confirmed_at = clock.now();
        sqlx::query!(
            r#"
                UPDATE user_emails
                SET confirmed_at = $2
                WHERE user_email_id = $1
            "#,
            Uuid::from(user_email.id),
            confirmed_at,
        )
        .execute(&mut *self.conn)
        .await?;

        user_email.confirmed_at = Some(confirmed_at);
        Ok(user_email)
    }

    #[tracing::instrument(
        name = "db.user_email.add_verification_code",
        skip_all,
        fields(
            db.query.text,
            %user_email.id,
            %user_email.email,
            user_email_verification.id,
            user_email_verification.code = code,
        ),
        err,
    )]
    async fn add_verification_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_email: &UserEmail,
        max_age: chrono::Duration,
        code: String,
    ) -> Result<UserEmailVerification, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_email_confirmation.id", tracing::field::display(id));
        let expires_at = created_at + max_age;

        sqlx::query!(
            r#"
                INSERT INTO user_email_confirmation_codes
                  (user_email_confirmation_code_id, user_email_id, code, created_at, expires_at)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(user_email.id),
            code,
            created_at,
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let verification = UserEmailVerification {
            id,
            user_email_id: user_email.id,
            code,
            created_at,
            state: UserEmailVerificationState::Valid,
        };

        Ok(verification)
    }

    #[tracing::instrument(
        name = "db.user_email.find_verification_code",
        skip_all,
        fields(
            db.query.text,
            %user_email.id,
            user.id = %user_email.user_id,
        ),
        err,
    )]
    async fn find_verification_code(
        &mut self,
        clock: &dyn Clock,
        user_email: &UserEmail,
        code: &str,
    ) -> Result<Option<UserEmailVerification>, Self::Error> {
        let res = sqlx::query_as!(
            UserEmailConfirmationCodeLookup,
            r#"
                SELECT user_email_confirmation_code_id
                     , user_email_id
                     , code
                     , created_at
                     , expires_at
                     , consumed_at
                FROM user_email_confirmation_codes
                WHERE code = $1
                  AND user_email_id = $2
            "#,
            code,
            Uuid::from(user_email.id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into_verification(clock)))
    }

    #[tracing::instrument(
        name = "db.user_email.consume_verification_code",
        skip_all,
        fields(
            db.query.text,
            %user_email_verification.id,
            user_email.id = %user_email_verification.user_email_id,
        ),
        err,
    )]
    async fn consume_verification_code(
        &mut self,
        clock: &dyn Clock,
        mut user_email_verification: UserEmailVerification,
    ) -> Result<UserEmailVerification, Self::Error> {
        if !matches!(
            user_email_verification.state,
            UserEmailVerificationState::Valid
        ) {
            return Err(DatabaseError::invalid_operation());
        }

        let consumed_at = clock.now();

        sqlx::query!(
            r#"
                UPDATE user_email_confirmation_codes
                SET consumed_at = $2
                WHERE user_email_confirmation_code_id = $1
            "#,
            Uuid::from(user_email_verification.id),
            consumed_at
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        user_email_verification.state =
            UserEmailVerificationState::AlreadyUsed { when: consumed_at };

        Ok(user_email_verification)
    }
}
