// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! A module containing PostgreSQL implementation of repositories for sessions

use async_trait::async_trait;
use mas_data_model::{
    CompatSession, CompatSessionState, Device, Session, SessionState, User, UserAgent,
};
use mas_storage::{
    Clock, Page, Pagination,
    app_session::{AppSession, AppSessionFilter, AppSessionRepository, AppSessionState},
    compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter,
};
use oauth2_types::scope::{Scope, ScopeToken};
use opentelemetry_semantic_conventions::trace::DB_QUERY_TEXT;
use sea_query::{
    Alias, ColumnRef, CommonTableExpression, Expr, PostgresQueryBuilder, Query, UnionType,
};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use tracing::Instrument;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, ExecuteExt,
    errors::DatabaseInconsistencyError,
    filter::StatementExt,
    iden::{CompatSessions, OAuth2Sessions},
    pagination::QueryBuilderExt,
};

/// An implementation of [`AppSessionRepository`] for a PostgreSQL connection
pub struct PgAppSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgAppSessionRepository<'c> {
    /// Create a new [`PgAppSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

mod priv_ {
    // The enum_def macro generates a public enum, which we don't want, because it
    // triggers the missing docs warning

    use std::net::IpAddr;

    use chrono::{DateTime, Utc};
    use sea_query::enum_def;
    use uuid::Uuid;

    #[derive(sqlx::FromRow)]
    #[enum_def]
    pub(super) struct AppSessionLookup {
        pub(super) cursor: Uuid,
        pub(super) compat_session_id: Option<Uuid>,
        pub(super) oauth2_session_id: Option<Uuid>,
        pub(super) oauth2_client_id: Option<Uuid>,
        pub(super) user_session_id: Option<Uuid>,
        pub(super) user_id: Option<Uuid>,
        pub(super) scope_list: Option<Vec<String>>,
        pub(super) device_id: Option<String>,
        pub(super) human_name: Option<String>,
        pub(super) created_at: DateTime<Utc>,
        pub(super) finished_at: Option<DateTime<Utc>>,
        pub(super) is_synapse_admin: Option<bool>,
        pub(super) user_agent: Option<String>,
        pub(super) last_active_at: Option<DateTime<Utc>>,
        pub(super) last_active_ip: Option<IpAddr>,
    }
}

use priv_::{AppSessionLookup, AppSessionLookupIden};

impl TryFrom<AppSessionLookup> for AppSession {
    type Error = DatabaseError;

    #[allow(clippy::too_many_lines)]
    fn try_from(value: AppSessionLookup) -> Result<Self, Self::Error> {
        // This is annoying to do, but we have to match on all the fields to determine
        // whether it's a compat session or an oauth2 session
        let AppSessionLookup {
            cursor,
            compat_session_id,
            oauth2_session_id,
            oauth2_client_id,
            user_session_id,
            user_id,
            scope_list,
            device_id,
            human_name,
            created_at,
            finished_at,
            is_synapse_admin,
            user_agent,
            last_active_at,
            last_active_ip,
        } = value;

        let user_agent = user_agent.map(UserAgent::parse);
        let user_session_id = user_session_id.map(Ulid::from);

        match (
            compat_session_id,
            oauth2_session_id,
            oauth2_client_id,
            user_id,
            scope_list,
            device_id,
            is_synapse_admin,
        ) {
            (
                Some(compat_session_id),
                None,
                None,
                Some(user_id),
                None,
                device_id_opt,
                Some(is_synapse_admin),
            ) => {
                let id = compat_session_id.into();
                let device = device_id_opt
                    .map(Device::try_from)
                    .transpose()
                    .map_err(|e| {
                        DatabaseInconsistencyError::on("compat_sessions")
                            .column("device_id")
                            .row(id)
                            .source(e)
                    })?;

                let state = match finished_at {
                    None => CompatSessionState::Valid,
                    Some(finished_at) => CompatSessionState::Finished { finished_at },
                };

                let session = CompatSession {
                    id,
                    state,
                    user_id: user_id.into(),
                    device,
                    human_name,
                    user_session_id,
                    created_at,
                    is_synapse_admin,
                    user_agent,
                    last_active_at,
                    last_active_ip,
                };

                Ok(AppSession::Compat(Box::new(session)))
            }

            (
                None,
                Some(oauth2_session_id),
                Some(oauth2_client_id),
                user_id,
                Some(scope_list),
                None,
                None,
            ) => {
                let id = oauth2_session_id.into();
                let scope: Result<Scope, _> =
                    scope_list.iter().map(|s| s.parse::<ScopeToken>()).collect();
                let scope = scope.map_err(|e| {
                    DatabaseInconsistencyError::on("oauth2_sessions")
                        .column("scope")
                        .row(id)
                        .source(e)
                })?;

                let state = match value.finished_at {
                    None => SessionState::Valid,
                    Some(finished_at) => SessionState::Finished { finished_at },
                };

                let session = Session {
                    id,
                    state,
                    created_at,
                    client_id: oauth2_client_id.into(),
                    user_id: user_id.map(Ulid::from),
                    user_session_id,
                    scope,
                    user_agent,
                    last_active_at,
                    last_active_ip,
                };

                Ok(AppSession::OAuth2(Box::new(session)))
            }

            _ => Err(DatabaseInconsistencyError::on("sessions")
                .row(cursor.into())
                .into()),
        }
    }
}

/// Split a [`AppSessionFilter`] into two separate filters: a
/// [`CompatSessionFilter`] and an [`OAuth2SessionFilter`].
fn split_filter(
    filter: AppSessionFilter<'_>,
) -> (CompatSessionFilter<'_>, OAuth2SessionFilter<'_>) {
    let mut compat_filter = CompatSessionFilter::new();
    let mut oauth2_filter = OAuth2SessionFilter::new();

    if let Some(user) = filter.user() {
        compat_filter = compat_filter.for_user(user);
        oauth2_filter = oauth2_filter.for_user(user);
    }

    match filter.state() {
        Some(AppSessionState::Active) => {
            compat_filter = compat_filter.active_only();
            oauth2_filter = oauth2_filter.active_only();
        }
        Some(AppSessionState::Finished) => {
            compat_filter = compat_filter.finished_only();
            oauth2_filter = oauth2_filter.finished_only();
        }
        None => {}
    }

    if let Some(device) = filter.device() {
        compat_filter = compat_filter.for_device(device);
        oauth2_filter = oauth2_filter.for_device(device);
    }

    if let Some(browser_session) = filter.browser_session() {
        compat_filter = compat_filter.for_browser_session(browser_session);
        oauth2_filter = oauth2_filter.for_browser_session(browser_session);
    }

    if let Some(last_active_before) = filter.last_active_before() {
        compat_filter = compat_filter.with_last_active_before(last_active_before);
        oauth2_filter = oauth2_filter.with_last_active_before(last_active_before);
    }

    if let Some(last_active_after) = filter.last_active_after() {
        compat_filter = compat_filter.with_last_active_after(last_active_after);
        oauth2_filter = oauth2_filter.with_last_active_after(last_active_after);
    }

    (compat_filter, oauth2_filter)
}

#[async_trait]
impl AppSessionRepository for PgAppSessionRepository<'_> {
    type Error = DatabaseError;

    #[allow(clippy::too_many_lines)]
    #[tracing::instrument(
        name = "db.app_session.list",
        fields(
            db.query.text,
        ),
        skip_all,
        err,
    )]
    async fn list(
        &mut self,
        filter: AppSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<AppSession>, Self::Error> {
        let (compat_filter, oauth2_filter) = split_filter(filter);

        let mut oauth2_session_select = Query::select()
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2SessionId)),
                AppSessionLookupIden::Cursor,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::CompatSessionId)
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2SessionId)),
                AppSessionLookupIden::Oauth2SessionId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2ClientId)),
                AppSessionLookupIden::Oauth2ClientId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserSessionId)),
                AppSessionLookupIden::UserSessionId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserId)),
                AppSessionLookupIden::UserId,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::ScopeList)),
                AppSessionLookupIden::ScopeList,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::DeviceId)
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::HumanName)
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::CreatedAt)),
                AppSessionLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt)),
                AppSessionLookupIden::FinishedAt,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::IsSynapseAdmin)
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::UserAgent)),
                AppSessionLookupIden::UserAgent,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::LastActiveAt)),
                AppSessionLookupIden::LastActiveAt,
            )
            .expr_as(
                Expr::col((OAuth2Sessions::Table, OAuth2Sessions::LastActiveIp)),
                AppSessionLookupIden::LastActiveIp,
            )
            .from(OAuth2Sessions::Table)
            .apply_filter(oauth2_filter)
            .clone();

        let compat_session_select = Query::select()
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId)),
                AppSessionLookupIden::Cursor,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CompatSessionId)),
                AppSessionLookupIden::CompatSessionId,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::Oauth2SessionId)
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::Oauth2ClientId)
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserSessionId)),
                AppSessionLookupIden::UserSessionId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserId)),
                AppSessionLookupIden::UserId,
            )
            .expr_as(Expr::cust("NULL"), AppSessionLookupIden::ScopeList)
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::DeviceId)),
                AppSessionLookupIden::DeviceId,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::HumanName)),
                AppSessionLookupIden::HumanName,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::CreatedAt)),
                AppSessionLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::FinishedAt)),
                AppSessionLookupIden::FinishedAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::IsSynapseAdmin)),
                AppSessionLookupIden::IsSynapseAdmin,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::UserAgent)),
                AppSessionLookupIden::UserAgent,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::LastActiveAt)),
                AppSessionLookupIden::LastActiveAt,
            )
            .expr_as(
                Expr::col((CompatSessions::Table, CompatSessions::LastActiveIp)),
                AppSessionLookupIden::LastActiveIp,
            )
            .from(CompatSessions::Table)
            .apply_filter(compat_filter)
            .clone();

        let common_table_expression = CommonTableExpression::new()
            .query(
                oauth2_session_select
                    .union(UnionType::All, compat_session_select)
                    .clone(),
            )
            .table_name(Alias::new("sessions"))
            .clone();

        let with_clause = Query::with().cte(common_table_expression).clone();

        let select = Query::select()
            .column(ColumnRef::Asterisk)
            .from(Alias::new("sessions"))
            .generate_pagination(AppSessionLookupIden::Cursor, pagination)
            .clone();

        let (sql, arguments) = with_clause.query(select).build_sqlx(PostgresQueryBuilder);

        let edges: Vec<AppSessionLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(TryFrom::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.app_session.count",
        fields(
            db.query.text,
        ),
        skip_all,
        err,
    )]
    async fn count(&mut self, filter: AppSessionFilter<'_>) -> Result<usize, Self::Error> {
        let (compat_filter, oauth2_filter) = split_filter(filter);
        let mut oauth2_session_select = Query::select()
            .expr(Expr::cust("1"))
            .from(OAuth2Sessions::Table)
            .apply_filter(oauth2_filter)
            .clone();

        let compat_session_select = Query::select()
            .expr(Expr::cust("1"))
            .from(CompatSessions::Table)
            .apply_filter(compat_filter)
            .clone();

        let common_table_expression = CommonTableExpression::new()
            .query(
                oauth2_session_select
                    .union(UnionType::All, compat_session_select)
                    .clone(),
            )
            .table_name(Alias::new("sessions"))
            .clone();

        let with_clause = Query::with().cte(common_table_expression).clone();

        let select = Query::select()
            .expr(Expr::cust("COUNT(*)"))
            .from(Alias::new("sessions"))
            .clone();

        let (sql, arguments) = with_clause.query(select).build_sqlx(PostgresQueryBuilder);

        let count: i64 = sqlx::query_scalar_with(&sql, arguments)
            .traced()
            .fetch_one(&mut *self.conn)
            .await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.app_session.finish_sessions_to_replace_device",
        fields(
            db.query.text,
            %user.id,
            %device_id = device.as_str()
        ),
        skip_all,
        err,
    )]
    async fn finish_sessions_to_replace_device(
        &mut self,
        clock: &dyn Clock,
        user: &User,
        device: &Device,
    ) -> Result<(), Self::Error> {
        // TODO need to invoke this from all the oauth2 login sites
        let span = tracing::info_span!(
            "db.app_session.finish_sessions_to_replace_device.compat_sessions",
            { DB_QUERY_TEXT } = tracing::field::Empty,
        );
        let finished_at = clock.now();
        sqlx::query!(
            "
                UPDATE compat_sessions SET finished_at = $3 WHERE user_id = $1 AND device_id = $2 AND finished_at IS NULL
            ",
            Uuid::from(user.id),
            device.as_str(),
            finished_at
        )
        .record(&span)
        .execute(&mut *self.conn)
        .instrument(span)
        .await?;

        if let Ok(device_as_scope_token) = device.to_scope_token() {
            let span = tracing::info_span!(
                "db.app_session.finish_sessions_to_replace_device.oauth2_sessions",
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );
            sqlx::query!(
                "
                    UPDATE oauth2_sessions SET finished_at = $3 WHERE user_id = $1 AND $2 = ANY(scope_list) AND finished_at IS NULL
                ",
                Uuid::from(user.id),
                device_as_scope_token.as_str(),
                finished_at
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_data_model::Device;
    use mas_storage::{
        Pagination, RepositoryAccess,
        app_session::{AppSession, AppSessionFilter},
        clock::MockClock,
        oauth2::OAuth2SessionRepository,
    };
    use oauth2_types::{
        requests::GrantType,
        scope::{OPENID, Scope},
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sqlx::PgPool;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_app_repo(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        let all = AppSessionFilter::new().for_user(&user);
        let active = all.active_only();
        let finished = all.finished_only();
        let pagination = Pagination::first(10);

        assert_eq!(repo.app_session().count(all).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 0);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert!(full_list.edges.is_empty());
        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert!(active_list.edges.is_empty());
        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert!(finished_list.edges.is_empty());

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let compat_session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device.clone(), None, false)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 0);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(
            full_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert_eq!(active_list.edges.len(), 1);
        assert_eq!(
            active_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert!(finished_list.edges.is_empty());

        // Finish the session
        let compat_session = repo
            .compat_session()
            .finish(&clock, compat_session)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 1);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 1);
        assert_eq!(
            full_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert!(active_list.edges.is_empty());
        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert_eq!(finished_list.edges.len(), 1);
        assert_eq!(
            finished_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );

        // Start an OAuth2 session
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("First client".to_owned()),
                Some("https://example.com/logo.png".parse().unwrap()),
                Some("https://example.com/".parse().unwrap()),
                Some("https://example.com/policy".parse().unwrap()),
                Some("https://example.com/tos".parse().unwrap()),
                Some("https://example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        let device2 = Device::generate(&mut rng);
        let scope = Scope::from_iter([OPENID, device2.to_scope_token().unwrap()]);

        // We're moving the clock forward by 1 minute between each session to ensure
        // we're getting consistent ordering in lists.
        clock.advance(Duration::try_minutes(1).unwrap());

        let oauth_session = repo
            .oauth2_session()
            .add(&mut rng, &clock, &client, Some(&user), None, scope)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 2);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 1);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 1);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 2);
        assert_eq!(
            full_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        assert_eq!(
            full_list.edges[1],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert_eq!(active_list.edges.len(), 1);
        assert_eq!(
            active_list.edges[0],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert_eq!(finished_list.edges.len(), 1);
        assert_eq!(
            finished_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );

        // Finish the session
        let oauth_session = repo
            .oauth2_session()
            .finish(&clock, oauth_session)
            .await
            .unwrap();

        assert_eq!(repo.app_session().count(all).await.unwrap(), 2);
        assert_eq!(repo.app_session().count(active).await.unwrap(), 0);
        assert_eq!(repo.app_session().count(finished).await.unwrap(), 2);

        let full_list = repo.app_session().list(all, pagination).await.unwrap();
        assert_eq!(full_list.edges.len(), 2);
        assert_eq!(
            full_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        assert_eq!(
            full_list.edges[1],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        let active_list = repo.app_session().list(active, pagination).await.unwrap();
        assert!(active_list.edges.is_empty());

        let finished_list = repo.app_session().list(finished, pagination).await.unwrap();
        assert_eq!(finished_list.edges.len(), 2);
        assert_eq!(
            finished_list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );
        assert_eq!(
            full_list.edges[1],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        // Query by device
        let filter = AppSessionFilter::new().for_device(&device);
        assert_eq!(repo.app_session().count(filter).await.unwrap(), 1);
        let list = repo.app_session().list(filter, pagination).await.unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(
            list.edges[0],
            AppSession::Compat(Box::new(compat_session.clone()))
        );

        let filter = AppSessionFilter::new().for_device(&device2);
        assert_eq!(repo.app_session().count(filter).await.unwrap(), 1);
        let list = repo.app_session().list(filter, pagination).await.unwrap();
        assert_eq!(list.edges.len(), 1);
        assert_eq!(
            list.edges[0],
            AppSession::OAuth2(Box::new(oauth_session.clone()))
        );

        // Create a second user
        let user2 = repo
            .user()
            .add(&mut rng, &clock, "alice".to_owned())
            .await
            .unwrap();

        // If we list/count for this user, we should get nothing
        let filter = AppSessionFilter::new().for_user(&user2);
        assert_eq!(repo.app_session().count(filter).await.unwrap(), 0);
        let list = repo.app_session().list(filter, pagination).await.unwrap();
        assert!(list.edges.is_empty());
    }
}
