// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    Clock, User,
    personal::session::{PersonalSession, PersonalSessionOwner, SessionState},
};
use mas_storage::{
    Page, Pagination,
    pagination::Node,
    personal::{PersonalSessionFilter, PersonalSessionRepository, PersonalSessionState},
};
use oauth2_types::scope::Scope;
use rand::RngCore;
use sea_query::{
    Condition, Expr, PgFunc, PostgresQueryBuilder, Query, SimpleExpr, enum_def,
    extension::postgres::PgExpr as _,
};
use sea_query_binder::SqlxBinder as _;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError,
    errors::DatabaseInconsistencyError,
    filter::{Filter, StatementExt as _},
    iden::PersonalSessions,
    pagination::QueryBuilderExt as _,
    tracing::ExecuteExt as _,
};

/// An implementation of [`PersonalSessionRepository`] for a PostgreSQL
/// connection
pub struct PgPersonalSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgPersonalSessionRepository<'c> {
    /// Create a new [`PgPersonalSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
#[enum_def]
struct PersonalSessionLookup {
    personal_session_id: Uuid,
    owner_user_id: Option<Uuid>,
    owner_oauth2_client_id: Option<Uuid>,
    actor_user_id: Uuid,
    human_name: String,
    scope_list: Vec<String>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<IpAddr>,
}

impl Node<Ulid> for PersonalSessionLookup {
    fn cursor(&self) -> Ulid {
        self.personal_session_id.into()
    }
}

impl TryFrom<PersonalSessionLookup> for PersonalSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: PersonalSessionLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.personal_session_id);
        let scope: Result<Scope, _> = value.scope_list.iter().map(|s| s.parse()).collect();
        let scope = scope.map_err(|e| {
            DatabaseInconsistencyError::on("personal_sessions")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match value.revoked_at {
            None => SessionState::Valid,
            Some(revoked_at) => SessionState::Revoked { revoked_at },
        };

        let owner = match (value.owner_user_id, value.owner_oauth2_client_id) {
            (Some(owner_user_id), None) => PersonalSessionOwner::User(Ulid::from(owner_user_id)),
            (None, Some(owner_oauth2_client_id)) => {
                PersonalSessionOwner::OAuth2Client(Ulid::from(owner_oauth2_client_id))
            }
            _ => {
                // should be impossible (CHECK constraint in Postgres prevents it)
                return Err(DatabaseInconsistencyError::on("personal_sessions")
                    .column("owner_user_id, owner_oauth2_client_id")
                    .row(id));
            }
        };

        Ok(PersonalSession {
            id,
            state,
            owner,
            actor_user_id: Ulid::from(value.actor_user_id),
            human_name: value.human_name,
            scope,
            created_at: value.created_at,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip,
        })
    }
}

#[async_trait]
impl PersonalSessionRepository for PgPersonalSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.personal_session.lookup",
        skip_all,
        fields(
            db.query.text,
            session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalSession>, Self::Error> {
        let res = sqlx::query_as!(
            PersonalSessionLookup,
            r#"
                SELECT personal_session_id
                     , owner_user_id
                     , owner_oauth2_client_id
                     , actor_user_id
                     , scope_list
                     , created_at
                     , revoked_at
                     , human_name
                     , last_active_at
                     , last_active_ip as "last_active_ip: IpAddr"
                FROM personal_sessions

                WHERE personal_session_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(session) = res else { return Ok(None) };

        Ok(Some(session.try_into()?))
    }

    #[tracing::instrument(
        name = "db.personal_session.add",
        skip_all,
        fields(
            db.query.text,
            session.id,
            session.scope = %scope,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        owner: PersonalSessionOwner,
        actor_user: &User,
        human_name: String,
        scope: Scope,
    ) -> Result<PersonalSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("session.id", tracing::field::display(id));

        let scope_list: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();

        let (owner_user_id, owner_oauth2_client_id) = match owner {
            PersonalSessionOwner::User(ulid) => (Some(Uuid::from(ulid)), None),
            PersonalSessionOwner::OAuth2Client(ulid) => (None, Some(Uuid::from(ulid))),
        };

        sqlx::query!(
            r#"
                INSERT INTO personal_sessions
                    ( personal_session_id
                    , owner_user_id
                    , owner_oauth2_client_id
                    , actor_user_id
                    , human_name
                    , scope_list
                    , created_at
                    )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            Uuid::from(id),
            owner_user_id,
            owner_oauth2_client_id,
            Uuid::from(actor_user.id),
            &human_name,
            &scope_list,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(PersonalSession {
            id,
            state: SessionState::Valid,
            owner,
            actor_user_id: actor_user.id,
            human_name,
            scope,
            created_at,
            last_active_at: None,
            last_active_ip: None,
        })
    }

    #[tracing::instrument(
        name = "db.personal_session.revoke",
        skip_all,
        fields(
            db.query.text,
            %session.id,
            %session.scope,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        session: PersonalSession,
    ) -> Result<PersonalSession, Self::Error> {
        let finished_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE personal_sessions
                SET revoked_at = $2
                WHERE personal_session_id = $1
            "#,
            Uuid::from(session.id),
            finished_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        session
            .finish(finished_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.personal_session.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: PersonalSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<PersonalSession>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((PersonalSessions::Table, PersonalSessions::PersonalSessionId)),
                PersonalSessionLookupIden::PersonalSessionId,
            )
            .expr_as(
                Expr::col((PersonalSessions::Table, PersonalSessions::OwnerUserId)),
                PersonalSessionLookupIden::OwnerUserId,
            )
            .expr_as(
                Expr::col((
                    PersonalSessions::Table,
                    PersonalSessions::OwnerOAuth2ClientId,
                )),
                PersonalSessionLookupIden::OwnerOauth2ClientId,
            )
            .expr_as(
                Expr::col((PersonalSessions::Table, PersonalSessions::ActorUserId)),
                PersonalSessionLookupIden::ActorUserId,
            )
            .expr_as(
                Expr::col((PersonalSessions::Table, PersonalSessions::HumanName)),
                PersonalSessionLookupIden::HumanName,
            )
            .expr_as(
                Expr::col((PersonalSessions::Table, PersonalSessions::ScopeList)),
                PersonalSessionLookupIden::ScopeList,
            )
            .expr_as(
                Expr::col((PersonalSessions::Table, PersonalSessions::CreatedAt)),
                PersonalSessionLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((PersonalSessions::Table, PersonalSessions::RevokedAt)),
                PersonalSessionLookupIden::RevokedAt,
            )
            .expr_as(
                Expr::col((PersonalSessions::Table, PersonalSessions::LastActiveAt)),
                PersonalSessionLookupIden::LastActiveAt,
            )
            .expr_as(
                Expr::col((PersonalSessions::Table, PersonalSessions::LastActiveIp)),
                PersonalSessionLookupIden::LastActiveIp,
            )
            .from(PersonalSessions::Table)
            .apply_filter(filter)
            .generate_pagination(
                (PersonalSessions::Table, PersonalSessions::PersonalSessionId),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<PersonalSessionLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(TryFrom::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.personal_session.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn count(&mut self, filter: PersonalSessionFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(Expr::col((PersonalSessions::Table, PersonalSessions::PersonalSessionId)).count())
            .from(PersonalSessions::Table)
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
        name = "db.personal_session.record_batch_activity",
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
                UPDATE personal_sessions
                SET last_active_at = GREATEST(t.last_active_at, personal_sessions.last_active_at)
                  , last_active_ip = COALESCE(t.last_active_ip, personal_sessions.last_active_ip)
                FROM (
                    SELECT *
                    FROM UNNEST($1::uuid[], $2::timestamptz[], $3::inet[])
                        AS t(personal_session_id, last_active_at, last_active_ip)
                ) AS t
                WHERE personal_sessions.personal_session_id = t.personal_session_id
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

impl Filter for PersonalSessionFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.owner_user().map(|user| {
                Expr::col((PersonalSessions::Table, PersonalSessions::OwnerUserId))
                    .eq(Uuid::from(user.id))
            }))
            .add_option(self.owner_oauth2_client().map(|client| {
                Expr::col((
                    PersonalSessions::Table,
                    PersonalSessions::OwnerOAuth2ClientId,
                ))
                .eq(Uuid::from(client.id))
            }))
            .add_option(self.actor_user().map(|user| {
                Expr::col((PersonalSessions::Table, PersonalSessions::ActorUserId))
                    .eq(Uuid::from(user.id))
            }))
            .add_option(self.device().map(|device| -> SimpleExpr {
                if let Ok([stable_scope_token, unstable_scope_token]) = device.to_scope_token() {
                    Condition::any()
                        .add(
                            Expr::val(stable_scope_token.to_string()).eq(PgFunc::any(Expr::col((
                                PersonalSessions::Table,
                                PersonalSessions::ScopeList,
                            )))),
                        )
                        .add(Expr::val(unstable_scope_token.to_string()).eq(PgFunc::any(
                            Expr::col((PersonalSessions::Table, PersonalSessions::ScopeList)),
                        )))
                        .into()
                } else {
                    // If the device ID can't be encoded as a scope token, match no rows
                    Expr::val(false).into()
                }
            }))
            .add_option(self.state().map(|state| match state {
                PersonalSessionState::Active => {
                    Expr::col((PersonalSessions::Table, PersonalSessions::RevokedAt)).is_null()
                }
                PersonalSessionState::Revoked => {
                    Expr::col((PersonalSessions::Table, PersonalSessions::RevokedAt)).is_not_null()
                }
            }))
            .add_option(self.scope().map(|scope| {
                let scope: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();
                Expr::col((PersonalSessions::Table, PersonalSessions::ScopeList)).contains(scope)
            }))
            .add_option(self.last_active_before().map(|last_active_before| {
                Expr::col((PersonalSessions::Table, PersonalSessions::LastActiveAt))
                    .lt(last_active_before)
            }))
            .add_option(self.last_active_after().map(|last_active_after| {
                Expr::col((PersonalSessions::Table, PersonalSessions::LastActiveAt))
                    .gt(last_active_after)
            }))
    }
}
