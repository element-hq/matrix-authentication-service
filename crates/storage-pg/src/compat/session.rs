// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    BrowserSession, CompatSession, CompatSessionState, CompatSsoLogin, CompatSsoLoginState, Device,
    User,
};
use mas_storage::{
    Clock, Page, Pagination,
    compat::{CompatSessionFilter, CompatSessionRepository},
};
use rand::RngCore;
use sea_query::{Expr, PostgresQueryBuilder, Query, enum_def};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    filter::{Filter, StatementExt, StatementWithJoinsExt},
    iden::{CompatSessions, CompatSsoLogins},
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

/// An implementation of [`CompatSessionRepository`] for a PostgreSQL connection
pub struct PgCompatSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgCompatSessionRepository<'c> {
    /// Create a new [`PgCompatSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct CompatSessionLookup {
    compat_session_id: Uuid,
    device_id: Option<String>,
    human_name: Option<String>,
    user_id: Uuid,
    user_session_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    is_synapse_admin: bool,
    user_agent: Option<String>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<IpAddr>,
}

impl From<CompatSessionLookup> for CompatSession {
    fn from(value: CompatSessionLookup) -> Self {
        let id = value.compat_session_id.into();

        let state = match value.finished_at {
            None => CompatSessionState::Valid,
            Some(finished_at) => CompatSessionState::Finished { finished_at },
        };

        CompatSession {
            id,
            state,
            user_id: value.user_id.into(),
            user_session_id: value.user_session_id.map(Ulid::from),
            device: value.device_id.map(Device::from),
            human_name: value.human_name,
            created_at: value.created_at,
            is_synapse_admin: value.is_synapse_admin,
            user_agent: value.user_agent,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip,
        }
    }
}

#[derive(sqlx::FromRow)]
#[enum_def]
struct CompatSessionAndSsoLoginLookup {
    compat_session_id: Uuid,
    device_id: Option<String>,
    human_name: Option<String>,
    user_id: Uuid,
    user_session_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    is_synapse_admin: bool,
    user_agent: Option<String>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<IpAddr>,
    compat_sso_login_id: Option<Uuid>,
    compat_sso_login_token: Option<String>,
    compat_sso_login_redirect_uri: Option<String>,
    compat_sso_login_created_at: Option<DateTime<Utc>>,
    compat_sso_login_fulfilled_at: Option<DateTime<Utc>>,
    compat_sso_login_exchanged_at: Option<DateTime<Utc>>,
}

impl TryFrom<CompatSessionAndSsoLoginLookup> for (CompatSession, Option<CompatSsoLogin>) {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: CompatSessionAndSsoLoginLookup) -> Result<Self, Self::Error> {
        let id = value.compat_session_id.into();

        let state = match value.finished_at {
            None => CompatSessionState::Valid,
            Some(finished_at) => CompatSessionState::Finished { finished_at },
        };

        let session = CompatSession {
            id,
            state,
            user_id: value.user_id.into(),
            device: value.device_id.map(Device::from),
            human_name: value.human_name,
            user_session_id: value.user_session_id.map(Ulid::from),
            created_at: value.created_at,
            is_synapse_admin: value.is_synapse_admin,
            user_agent: value.user_agent,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip,
        };

        match (
            value.compat_sso_login_id,
            value.compat_sso_login_token,
            value.compat_sso_login_redirect_uri,
            value.compat_sso_login_created_at,
            value.compat_sso_login_fulfilled_at,
            value.compat_sso_login_exchanged_at,
        ) {
            (None, None, None, None, None, None) => Ok((session, None)),
            (
                Some(id),
                Some(login_token),
                Some(redirect_uri),
                Some(created_at),
                fulfilled_at,
                exchanged_at,
            ) => {
                let id = id.into();
                let redirect_uri = Url::parse(&redirect_uri).map_err(|e| {
                    DatabaseInconsistencyError::on("compat_sso_logins")
                        .column("redirect_uri")
                        .row(id)
                        .source(e)
                })?;

                let state = match (fulfilled_at, exchanged_at) {
                    (Some(fulfilled_at), Some(exchanged_at)) => CompatSsoLoginState::Exchanged {
                        fulfilled_at,
                        exchanged_at,
                        compat_session_id: session.id,
                    },
                    _ => return Err(DatabaseInconsistencyError::on("compat_sso_logins").row(id)),
                };

                let login = CompatSsoLogin {
                    id,
                    redirect_uri,
                    login_token,
                    created_at,
                    state,
                };

                Ok((session, Some(login)))
            }
            _ => Err(DatabaseInconsistencyError::on("compat_sso_logins").row(id)),
        }
    }
}

impl Filter for CompatSessionFilter<'_> {
    fn generate_condition(&self, has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.user().map(|user| {
                Expr::col((CompatSessions::Table, CompatSessions::UserId)).eq(Uuid::from(user.id))
            }))
            .add_option(self.browser_session().map(|browser_session| {
                Expr::col((CompatSessions::Table, CompatSessions::UserSessionId))
                    .eq(Uuid::from(browser_session.id))
            }))
            .add_option(self.state().map(|state| {
                if state.is_active() {
                    Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)).is_null()
                } else {
                    Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)).is_not_null()
                }
            }))
            .add_option(self.auth_type().map(|auth_type| {
                // In in the SELECT to list sessions, we can rely on the JOINed table, whereas
                // in other queries we need to do a subquery
                if has_joins {
                    if auth_type.is_sso_login() {
                        Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSsoLoginId))
                            .is_not_null()
                    } else {
                        Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSsoLoginId))
                            .is_null()
                    }
                } else {
                    // This builds either a:
                    // `WHERE compat_session_id = ANY(...)`
                    // or a `WHERE compat_session_id <> ALL(...)`
                    let compat_sso_logins = Query::select()
                        .expr(Expr::col((
                            CompatSsoLogins::Table,
                            CompatSsoLogins::CompatSessionId,
                        )))
                        .from(CompatSsoLogins::Table)
                        .take();

                    if auth_type.is_sso_login() {
                        Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId))
                            .eq(Expr::any(compat_sso_logins))
                    } else {
                        Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId))
                            .ne(Expr::all(compat_sso_logins))
                    }
                }
            }))
            .add_option(self.last_active_after().map(|last_active_after| {
                Expr::col((CompatSessions::Table, CompatSessions::LastActiveAt))
                    .gt(last_active_after)
            }))
            .add_option(self.last_active_before().map(|last_active_before| {
                Expr::col((CompatSessions::Table, CompatSessions::LastActiveAt))
                    .lt(last_active_before)
            }))
            .add_option(self.device().map(|device| {
                Expr::col((CompatSessions::Table, CompatSessions::DeviceId)).eq(device.as_str())
            }))
    }
}

#[async_trait]
impl CompatSessionRepository for PgCompatSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.compat_session.lookup",
        skip_all,
        fields(
            db.query.text,
            compat_session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSession>, Self::Error> {
        let res = sqlx::query_as!(
            CompatSessionLookup,
            r#"
                SELECT compat_session_id
                     , device_id
                     , human_name
                     , user_id
                     , user_session_id
                     , created_at
                     , finished_at
                     , is_synapse_admin
                     , user_agent
                     , last_active_at
                     , last_active_ip as "last_active_ip: IpAddr"
                FROM compat_sessions
                WHERE compat_session_id = $1
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
        name = "db.compat_session.add",
        skip_all,
        fields(
            db.query.text,
            compat_session.id,
            %user.id,
            %user.username,
            compat_session.device.id = device.as_str(),
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        device: Device,
        browser_session: Option<&BrowserSession>,
        is_synapse_admin: bool,
        human_name: Option<String>,
    ) -> Result<CompatSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("compat_session.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO compat_sessions
                    (compat_session_id, user_id, device_id,
                     user_session_id, created_at, is_synapse_admin,
                     human_name)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            device.as_str(),
            browser_session.map(|s| Uuid::from(s.id)),
            created_at,
            is_synapse_admin,
            human_name.as_deref(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(CompatSession {
            id,
            state: CompatSessionState::default(),
            user_id: user.id,
            device: Some(device),
            human_name,
            user_session_id: browser_session.map(|s| s.id),
            created_at,
            is_synapse_admin,
            user_agent: None,
            last_active_at: None,
            last_active_ip: None,
        })
    }

    #[tracing::instrument(
        name = "db.compat_session.finish",
        skip_all,
        fields(
            db.query.text,
            %compat_session.id,
            user.id = %compat_session.user_id,
            compat_session.device.id = compat_session.device.as_ref().map(mas_data_model::Device::as_str),
        ),
        err,
    )]
    async fn finish(
        &mut self,
        clock: &dyn Clock,
        compat_session: CompatSession,
    ) -> Result<CompatSession, Self::Error> {
        let finished_at = clock.now();

        let res = sqlx::query!(
            r#"
                UPDATE compat_sessions cs
                SET finished_at = $2
                WHERE compat_session_id = $1
            "#,
            Uuid::from(compat_session.id),
            finished_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        let compat_session = compat_session
            .finish(finished_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(compat_session)
    }

    #[tracing::instrument(
        name = "db.compat_session.finish_bulk",
        skip_all,
        fields(db.query.text),
        err,
    )]
    async fn finish_bulk(
        &mut self,
        clock: &dyn Clock,
        filter: CompatSessionFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let finished_at = clock.now();
        let (sql, arguments) = Query::update()
            .table(CompatSessions::Table)
            .value(CompatSessions::FinishedAt, finished_at)
            .apply_filter(filter)
            .build_sqlx(PostgresQueryBuilder);

        let res = sqlx::query_with(&sql, arguments)
            .traced()
            .execute(&mut *self.conn)
            .await?;

        Ok(res.rows_affected().try_into().unwrap_or(usize::MAX))
    }

    #[tracing::instrument(
        name = "db.compat_session.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: CompatSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<(CompatSession, Option<CompatSsoLogin>)>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId)),
                CompatSessionAndSsoLoginLookupIden::CompatSessionId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::DeviceId)),
                CompatSessionAndSsoLoginLookupIden::DeviceId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::HumanName)),
                CompatSessionAndSsoLoginLookupIden::HumanName,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserId)),
                CompatSessionAndSsoLoginLookupIden::UserId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserSessionId)),
                CompatSessionAndSsoLoginLookupIden::UserSessionId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CreatedAt)),
                CompatSessionAndSsoLoginLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)),
                CompatSessionAndSsoLoginLookupIden::FinishedAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::IsSynapseAdmin)),
                CompatSessionAndSsoLoginLookupIden::IsSynapseAdmin,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserAgent)),
                CompatSessionAndSsoLoginLookupIden::UserAgent,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::LastActiveAt)),
                CompatSessionAndSsoLoginLookupIden::LastActiveAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::LastActiveIp)),
                CompatSessionAndSsoLoginLookupIden::LastActiveIp,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSsoLoginId)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginId,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::LoginToken)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginToken,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::RedirectUri)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginRedirectUri,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CreatedAt)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginCreatedAt,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::FulfilledAt)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginFulfilledAt,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::ExchangedAt)),
                CompatSessionAndSsoLoginLookupIden::CompatSsoLoginExchangedAt,
            )
            .from(CompatSessions::Table)
            .left_join(
                CompatSsoLogins::Table,
                Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId))
                    .equals((CompatSsoLogins::Table, CompatSsoLogins::CompatSessionId)),
            )
            .apply_filter_with_joins(filter)
            .generate_pagination(
                (CompatSessions::Table, CompatSessions::CompatSessionId),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<CompatSessionAndSsoLoginLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(TryFrom::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.compat_session.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn count(&mut self, filter: CompatSessionFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = sea_query::Query::select()
            .expr(Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId)).count())
            .from(CompatSessions::Table)
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
        name = "db.compat_session.record_batch_activity",
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
                UPDATE compat_sessions
                SET last_active_at = GREATEST(t.last_active_at, compat_sessions.last_active_at)
                  , last_active_ip = COALESCE(t.last_active_ip, compat_sessions.last_active_ip)
                FROM (
                    SELECT *
                    FROM UNNEST($1::uuid[], $2::timestamptz[], $3::inet[])
                        AS t(compat_session_id, last_active_at, last_active_ip)
                ) AS t
                WHERE compat_sessions.compat_session_id = t.compat_session_id
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

    #[tracing::instrument(
        name = "db.compat_session.record_user_agent",
        skip_all,
        fields(
            db.query.text,
            %compat_session.id,
        ),
        err,
    )]
    async fn record_user_agent(
        &mut self,
        mut compat_session: CompatSession,
        user_agent: String,
    ) -> Result<CompatSession, Self::Error> {
        let res = sqlx::query!(
            r#"
            UPDATE compat_sessions
            SET user_agent = $2
            WHERE compat_session_id = $1
        "#,
            Uuid::from(compat_session.id),
            &*user_agent,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        compat_session.user_agent = Some(user_agent);

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(compat_session)
    }

    #[tracing::instrument(
        name = "repository.compat_session.set_human_name",
        skip(self),
        fields(
            compat_session.id = %compat_session.id,
            compat_session.human_name = ?human_name,
        ),
        err,
    )]
    async fn set_human_name(
        &mut self,
        mut compat_session: CompatSession,
        human_name: Option<String>,
    ) -> Result<CompatSession, Self::Error> {
        let res = sqlx::query!(
            r#"
            UPDATE compat_sessions
            SET human_name = $2
            WHERE compat_session_id = $1
        "#,
            Uuid::from(compat_session.id),
            human_name.as_deref(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        compat_session.human_name = human_name;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(compat_session)
    }
}
