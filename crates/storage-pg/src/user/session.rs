// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    Authentication, AuthenticationMethod, BrowserSession, Password,
    UpstreamOAuthAuthorizationSession, User,
};
use mas_storage::{
    Clock, Page, Pagination,
    user::{BrowserSessionFilter, BrowserSessionRepository},
};
use rand::RngCore;
use sea_query::{Expr, PostgresQueryBuilder};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    filter::StatementExt,
    iden::{UserSessions, Users},
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

/// An implementation of [`BrowserSessionRepository`] for a PostgreSQL
/// connection
pub struct PgBrowserSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgBrowserSessionRepository<'c> {
    /// Create a new [`PgBrowserSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[allow(clippy::struct_field_names)]
#[derive(sqlx::FromRow)]
#[sea_query::enum_def]
struct SessionLookup {
    user_session_id: Uuid,
    user_session_created_at: DateTime<Utc>,
    user_session_finished_at: Option<DateTime<Utc>>,
    user_session_user_agent: Option<String>,
    user_session_last_active_at: Option<DateTime<Utc>>,
    user_session_last_active_ip: Option<IpAddr>,
    user_id: Uuid,
    user_username: String,
    user_created_at: DateTime<Utc>,
    user_locked_at: Option<DateTime<Utc>>,
    user_deactivated_at: Option<DateTime<Utc>>,
    user_can_request_admin: bool,
}

impl TryFrom<SessionLookup> for BrowserSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: SessionLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.user_id);
        let user = User {
            id,
            username: value.user_username,
            sub: id.to_string(),
            created_at: value.user_created_at,
            locked_at: value.user_locked_at,
            deactivated_at: value.user_deactivated_at,
            can_request_admin: value.user_can_request_admin,
        };

        Ok(BrowserSession {
            id: value.user_session_id.into(),
            user,
            created_at: value.user_session_created_at,
            finished_at: value.user_session_finished_at,
            user_agent: value.user_session_user_agent,
            last_active_at: value.user_session_last_active_at,
            last_active_ip: value.user_session_last_active_ip,
        })
    }
}

struct AuthenticationLookup {
    user_session_authentication_id: Uuid,
    created_at: DateTime<Utc>,
    user_password_id: Option<Uuid>,
    upstream_oauth_authorization_session_id: Option<Uuid>,
}

impl TryFrom<AuthenticationLookup> for Authentication {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: AuthenticationLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.user_session_authentication_id);
        let authentication_method = match (
            value.user_password_id.map(Into::into),
            value
                .upstream_oauth_authorization_session_id
                .map(Into::into),
        ) {
            (Some(user_password_id), None) => AuthenticationMethod::Password { user_password_id },
            (None, Some(upstream_oauth2_session_id)) => AuthenticationMethod::UpstreamOAuth2 {
                upstream_oauth2_session_id,
            },
            (None, None) => AuthenticationMethod::Unknown,
            _ => {
                return Err(DatabaseInconsistencyError::on("user_session_authentications").row(id));
            }
        };

        Ok(Authentication {
            id,
            created_at: value.created_at,
            authentication_method,
        })
    }
}

impl crate::filter::Filter for BrowserSessionFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.user().map(|user| {
                Expr::col((UserSessions::Table, UserSessions::UserId)).eq(Uuid::from(user.id))
            }))
            .add_option(self.state().map(|state| {
                if state.is_active() {
                    Expr::col((UserSessions::Table, UserSessions::FinishedAt)).is_null()
                } else {
                    Expr::col((UserSessions::Table, UserSessions::FinishedAt)).is_not_null()
                }
            }))
            .add_option(self.last_active_after().map(|last_active_after| {
                Expr::col((UserSessions::Table, UserSessions::LastActiveAt)).gt(last_active_after)
            }))
            .add_option(self.last_active_before().map(|last_active_before| {
                Expr::col((UserSessions::Table, UserSessions::LastActiveAt)).lt(last_active_before)
            }))
    }
}

#[async_trait]
impl BrowserSessionRepository for PgBrowserSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.browser_session.lookup",
        skip_all,
        fields(
            db.query.text,
            user_session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<BrowserSession>, Self::Error> {
        let res = sqlx::query_as!(
            SessionLookup,
            r#"
                SELECT s.user_session_id
                     , s.created_at            AS "user_session_created_at"
                     , s.finished_at           AS "user_session_finished_at"
                     , s.user_agent            AS "user_session_user_agent"
                     , s.last_active_at        AS "user_session_last_active_at"
                     , s.last_active_ip        AS "user_session_last_active_ip: IpAddr"
                     , u.user_id
                     , u.username              AS "user_username"
                     , u.created_at            AS "user_created_at"
                     , u.locked_at             AS "user_locked_at"
                     , u.deactivated_at        AS "user_deactivated_at"
                     , u.can_request_admin     AS "user_can_request_admin"
                FROM user_sessions s
                INNER JOIN users u
                    USING (user_id)
                WHERE s.user_session_id = $1
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
        name = "db.browser_session.add",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            user_session.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        user_agent: Option<String>,
    ) -> Result<BrowserSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_session.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO user_sessions (user_session_id, user_id, created_at, user_agent)
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            created_at,
            user_agent.as_deref(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let session = BrowserSession {
            id,
            // XXX
            user: user.clone(),
            created_at,
            finished_at: None,
            user_agent,
            last_active_at: None,
            last_active_ip: None,
        };

        Ok(session)
    }

    #[tracing::instrument(
        name = "db.browser_session.finish",
        skip_all,
        fields(
            db.query.text,
            %user_session.id,
        ),
        err,
    )]
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        mut user_session: BrowserSession,
    ) -> Result<BrowserSession, Self::Error> {
        let finished_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE user_sessions
                SET finished_at = $1
                WHERE user_session_id = $2
            "#,
            finished_at,
            Uuid::from(user_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        user_session.finished_at = Some(finished_at);

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(user_session)
    }

    #[tracing::instrument(
        name = "db.browser_session.finish_bulk",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn finish_bulk(
        &mut self,
        clock: &dyn Clock,
        filter: BrowserSessionFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let finished_at = clock.now();
        let (sql, arguments) = sea_query::Query::update()
            .table(UserSessions::Table)
            .value(UserSessions::FinishedAt, finished_at)
            .apply_filter(filter)
            .build_sqlx(PostgresQueryBuilder);

        let res = sqlx::query_with(&sql, arguments)
            .traced()
            .execute(&mut *self.conn)
            .await?;

        Ok(res.rows_affected().try_into().unwrap_or(usize::MAX))
    }

    #[tracing::instrument(
        name = "db.browser_session.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: BrowserSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<BrowserSession>, Self::Error> {
        let (sql, arguments) = sea_query::Query::select()
            .expr_as(
                Expr::col((UserSessions::Table, UserSessions::UserSessionId)),
                SessionLookupIden::UserSessionId,
            )
            .expr_as(
                Expr::col((UserSessions::Table, UserSessions::CreatedAt)),
                SessionLookupIden::UserSessionCreatedAt,
            )
            .expr_as(
                Expr::col((UserSessions::Table, UserSessions::FinishedAt)),
                SessionLookupIden::UserSessionFinishedAt,
            )
            .expr_as(
                Expr::col((UserSessions::Table, UserSessions::UserAgent)),
                SessionLookupIden::UserSessionUserAgent,
            )
            .expr_as(
                Expr::col((UserSessions::Table, UserSessions::LastActiveAt)),
                SessionLookupIden::UserSessionLastActiveAt,
            )
            .expr_as(
                Expr::col((UserSessions::Table, UserSessions::LastActiveIp)),
                SessionLookupIden::UserSessionLastActiveIp,
            )
            .expr_as(
                Expr::col((Users::Table, Users::UserId)),
                SessionLookupIden::UserId,
            )
            .expr_as(
                Expr::col((Users::Table, Users::Username)),
                SessionLookupIden::UserUsername,
            )
            .expr_as(
                Expr::col((Users::Table, Users::CreatedAt)),
                SessionLookupIden::UserCreatedAt,
            )
            .expr_as(
                Expr::col((Users::Table, Users::LockedAt)),
                SessionLookupIden::UserLockedAt,
            )
            .expr_as(
                Expr::col((Users::Table, Users::DeactivatedAt)),
                SessionLookupIden::UserDeactivatedAt,
            )
            .expr_as(
                Expr::col((Users::Table, Users::CanRequestAdmin)),
                SessionLookupIden::UserCanRequestAdmin,
            )
            .from(UserSessions::Table)
            .inner_join(
                Users::Table,
                Expr::col((UserSessions::Table, UserSessions::UserId))
                    .equals((Users::Table, Users::UserId)),
            )
            .apply_filter(filter)
            .generate_pagination(
                (UserSessions::Table, UserSessions::UserSessionId),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<SessionLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination
            .process(edges)
            .try_map(BrowserSession::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.browser_session.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn count(&mut self, filter: BrowserSessionFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = sea_query::Query::select()
            .expr(Expr::col((UserSessions::Table, UserSessions::UserSessionId)).count())
            .from(UserSessions::Table)
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
        name = "db.browser_session.authenticate_with_password",
        skip_all,
        fields(
            db.query.text,
            %user_session.id,
            %user_password.id,
            user_session_authentication.id,
        ),
        err,
    )]
    async fn authenticate_with_password(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: &BrowserSession,
        user_password: &Password,
    ) -> Result<Authentication, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record(
            "user_session_authentication.id",
            tracing::field::display(id),
        );

        sqlx::query!(
            r#"
                INSERT INTO user_session_authentications
                    (user_session_authentication_id, user_session_id, created_at, user_password_id)
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(user_session.id),
            created_at,
            Uuid::from(user_password.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(Authentication {
            id,
            created_at,
            authentication_method: AuthenticationMethod::Password {
                user_password_id: user_password.id,
            },
        })
    }

    #[tracing::instrument(
        name = "db.browser_session.authenticate_with_upstream",
        skip_all,
        fields(
            db.query.text,
            %user_session.id,
            %upstream_oauth_session.id,
            user_session_authentication.id,
        ),
        err,
    )]
    async fn authenticate_with_upstream(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_session: &BrowserSession,
        upstream_oauth_session: &UpstreamOAuthAuthorizationSession,
    ) -> Result<Authentication, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record(
            "user_session_authentication.id",
            tracing::field::display(id),
        );

        sqlx::query!(
            r#"
                INSERT INTO user_session_authentications
                    (user_session_authentication_id, user_session_id, created_at, upstream_oauth_authorization_session_id)
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            Uuid::from(user_session.id),
            created_at,
            Uuid::from(upstream_oauth_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(Authentication {
            id,
            created_at,
            authentication_method: AuthenticationMethod::UpstreamOAuth2 {
                upstream_oauth2_session_id: upstream_oauth_session.id,
            },
        })
    }

    #[tracing::instrument(
        name = "db.browser_session.get_last_authentication",
        skip_all,
        fields(
            db.query.text,
            %user_session.id,
        ),
        err,
    )]
    async fn get_last_authentication(
        &mut self,
        user_session: &BrowserSession,
    ) -> Result<Option<Authentication>, Self::Error> {
        let authentication = sqlx::query_as!(
            AuthenticationLookup,
            r#"
                SELECT user_session_authentication_id
                     , created_at
                     , user_password_id
                     , upstream_oauth_authorization_session_id
                FROM user_session_authentications
                WHERE user_session_id = $1
                ORDER BY created_at DESC
                LIMIT 1
            "#,
            Uuid::from(user_session.id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(authentication) = authentication else {
            return Ok(None);
        };

        let authentication = Authentication::try_from(authentication)?;
        Ok(Some(authentication))
    }

    #[tracing::instrument(
        name = "db.browser_session.record_batch_activity",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn record_batch_activity(
        &mut self,
        mut activities: Vec<(Ulid, DateTime<Utc>, Option<IpAddr>)>,
    ) -> Result<(), Self::Error> {
        // Sort the activity by ID, so that when batching the updates, Postgres
        // locks the rows in a stable order, preventing deadlocks
        activities.sort_unstable();
        let mut ids = Vec::with_capacity(activities.len());
        let mut last_activities = Vec::with_capacity(activities.len());
        let mut ips = Vec::with_capacity(activities.len());

        for (id, last_activity, ip) in activities {
            ids.push(Uuid::from(id));
            last_activities.push(last_activity);
            ips.push(ip);
        }

        let res = sqlx::query!(
            r#"
                UPDATE user_sessions
                SET last_active_at = GREATEST(t.last_active_at, user_sessions.last_active_at)
                  , last_active_ip = COALESCE(t.last_active_ip, user_sessions.last_active_ip)
                FROM (
                    SELECT *
                    FROM UNNEST($1::uuid[], $2::timestamptz[], $3::inet[])
                        AS t(user_session_id, last_active_at, last_active_ip)
                ) AS t
                WHERE user_sessions.user_session_id = t.user_session_id
            "#,
            &ids,
            &last_activities,
            &ips as &[Option<IpAddr>],
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, ids.len().try_into().unwrap_or(u64::MAX))?;

        Ok(())
    }
}
