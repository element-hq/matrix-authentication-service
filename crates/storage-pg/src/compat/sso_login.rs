// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{BrowserSession, CompatSession, CompatSsoLogin, CompatSsoLoginState};
use mas_storage::{
    Clock, Page, Pagination,
    compat::{CompatSsoLoginFilter, CompatSsoLoginRepository},
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
    filter::{Filter, StatementExt},
    iden::{CompatSsoLogins, UserSessions},
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

/// An implementation of [`CompatSsoLoginRepository`] for a PostgreSQL
/// connection
pub struct PgCompatSsoLoginRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgCompatSsoLoginRepository<'c> {
    /// Create a new [`PgCompatSsoLoginRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow, Debug)]
#[enum_def]
struct CompatSsoLoginLookup {
    compat_sso_login_id: Uuid,
    login_token: String,
    redirect_uri: String,
    created_at: DateTime<Utc>,
    fulfilled_at: Option<DateTime<Utc>>,
    exchanged_at: Option<DateTime<Utc>>,
    user_session_id: Option<Uuid>,
    compat_session_id: Option<Uuid>,
}

impl TryFrom<CompatSsoLoginLookup> for CompatSsoLogin {
    type Error = DatabaseInconsistencyError;

    fn try_from(res: CompatSsoLoginLookup) -> Result<Self, Self::Error> {
        let id = res.compat_sso_login_id.into();
        let redirect_uri = Url::parse(&res.redirect_uri).map_err(|e| {
            DatabaseInconsistencyError::on("compat_sso_logins")
                .column("redirect_uri")
                .row(id)
                .source(e)
        })?;

        let state = match (
            res.fulfilled_at,
            res.exchanged_at,
            res.user_session_id,
            res.compat_session_id,
        ) {
            (None, None, None, None) => CompatSsoLoginState::Pending,
            (Some(fulfilled_at), None, Some(browser_session_id), None) => {
                CompatSsoLoginState::Fulfilled {
                    fulfilled_at,
                    browser_session_id: browser_session_id.into(),
                }
            }
            (Some(fulfilled_at), Some(exchanged_at), _, Some(compat_session_id)) => {
                CompatSsoLoginState::Exchanged {
                    fulfilled_at,
                    exchanged_at,
                    compat_session_id: compat_session_id.into(),
                }
            }
            _ => return Err(DatabaseInconsistencyError::on("compat_sso_logins").row(id)),
        };

        Ok(CompatSsoLogin {
            id,
            login_token: res.login_token,
            redirect_uri,
            created_at: res.created_at,
            state,
        })
    }
}

impl Filter for CompatSsoLoginFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.user().map(|user| {
                Expr::exists(
                    Query::select()
                        .expr(Expr::cust("1"))
                        .from(UserSessions::Table)
                        .and_where(
                            Expr::col((UserSessions::Table, UserSessions::UserId))
                                .eq(Uuid::from(user.id)),
                        )
                        .and_where(
                            Expr::col((CompatSsoLogins::Table, CompatSsoLogins::UserSessionId))
                                .equals((UserSessions::Table, UserSessions::UserSessionId)),
                        )
                        .take(),
                )
            }))
            .add_option(self.state().map(|state| {
                if state.is_exchanged() {
                    Expr::col((CompatSsoLogins::Table, CompatSsoLogins::ExchangedAt)).is_not_null()
                } else if state.is_fulfilled() {
                    Expr::col((CompatSsoLogins::Table, CompatSsoLogins::FulfilledAt))
                        .is_not_null()
                        .and(
                            Expr::col((CompatSsoLogins::Table, CompatSsoLogins::ExchangedAt))
                                .is_null(),
                        )
                } else {
                    Expr::col((CompatSsoLogins::Table, CompatSsoLogins::FulfilledAt)).is_null()
                }
            }))
    }
}

#[async_trait]
impl CompatSsoLoginRepository for PgCompatSsoLoginRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.compat_sso_login.lookup",
        skip_all,
        fields(
            db.query.text,
            compat_sso_login.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatSsoLogin>, Self::Error> {
        let res = sqlx::query_as!(
            CompatSsoLoginLookup,
            r#"
                SELECT compat_sso_login_id
                     , login_token
                     , redirect_uri
                     , created_at
                     , fulfilled_at
                     , exchanged_at
                     , compat_session_id
                     , user_session_id

                FROM compat_sso_logins
                WHERE compat_sso_login_id = $1
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
        name = "db.compat_sso_login.find_for_session",
        skip_all,
        fields(
            db.query.text,
            %compat_session.id,
        ),
        err,
    )]
    async fn find_for_session(
        &mut self,
        compat_session: &CompatSession,
    ) -> Result<Option<CompatSsoLogin>, Self::Error> {
        let res = sqlx::query_as!(
            CompatSsoLoginLookup,
            r#"
                SELECT compat_sso_login_id
                     , login_token
                     , redirect_uri
                     , created_at
                     , fulfilled_at
                     , exchanged_at
                     , compat_session_id
                     , user_session_id

                FROM compat_sso_logins
                WHERE compat_session_id = $1
            "#,
            Uuid::from(compat_session.id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.find_by_token",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        login_token: &str,
    ) -> Result<Option<CompatSsoLogin>, Self::Error> {
        let res = sqlx::query_as!(
            CompatSsoLoginLookup,
            r#"
                SELECT compat_sso_login_id
                     , login_token
                     , redirect_uri
                     , created_at
                     , fulfilled_at
                     , exchanged_at
                     , compat_session_id
                     , user_session_id

                FROM compat_sso_logins
                WHERE login_token = $1
            "#,
            login_token,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.add",
        skip_all,
        fields(
            db.query.text,
            compat_sso_login.id,
            compat_sso_login.redirect_uri = %redirect_uri,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        login_token: String,
        redirect_uri: Url,
    ) -> Result<CompatSsoLogin, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("compat_sso_login.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO compat_sso_logins
                    (compat_sso_login_id, login_token, redirect_uri, created_at)
                VALUES ($1, $2, $3, $4)
            "#,
            Uuid::from(id),
            &login_token,
            redirect_uri.as_str(),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(CompatSsoLogin {
            id,
            login_token,
            redirect_uri,
            created_at,
            state: CompatSsoLoginState::default(),
        })
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.fulfill",
        skip_all,
        fields(
            db.query.text,
            %compat_sso_login.id,
            %browser_session.id,
            user.id = %browser_session.user.id,
        ),
        err,
    )]
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
        browser_session: &BrowserSession,
    ) -> Result<CompatSsoLogin, Self::Error> {
        let fulfilled_at = clock.now();
        let compat_sso_login = compat_sso_login
            .fulfill(fulfilled_at, browser_session)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE compat_sso_logins
                SET
                    user_session_id = $2,
                    fulfilled_at = $3
                WHERE
                    compat_sso_login_id = $1
            "#,
            Uuid::from(compat_sso_login.id),
            Uuid::from(browser_session.id),
            fulfilled_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(compat_sso_login)
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.exchange",
        skip_all,
        fields(
            db.query.text,
            %compat_sso_login.id,
            %compat_session.id,
            compat_session.device.id = compat_session.device.as_ref().map(mas_data_model::Device::as_str),
        ),
        err,
    )]
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        compat_sso_login: CompatSsoLogin,
        compat_session: &CompatSession,
    ) -> Result<CompatSsoLogin, Self::Error> {
        let exchanged_at = clock.now();
        let compat_sso_login = compat_sso_login
            .exchange(exchanged_at, compat_session)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE compat_sso_logins
                SET
                    exchanged_at = $2,
                    compat_session_id = $3
                WHERE
                    compat_sso_login_id = $1
            "#,
            Uuid::from(compat_sso_login.id),
            exchanged_at,
            Uuid::from(compat_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(compat_sso_login)
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err
    )]
    async fn list(
        &mut self,
        filter: CompatSsoLoginFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<CompatSsoLogin>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSsoLoginId)),
                CompatSsoLoginLookupIden::CompatSsoLoginId,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSessionId)),
                CompatSsoLoginLookupIden::CompatSessionId,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::UserSessionId)),
                CompatSsoLoginLookupIden::UserSessionId,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::LoginToken)),
                CompatSsoLoginLookupIden::LoginToken,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::RedirectUri)),
                CompatSsoLoginLookupIden::RedirectUri,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CreatedAt)),
                CompatSsoLoginLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::FulfilledAt)),
                CompatSsoLoginLookupIden::FulfilledAt,
            )
            .expr_as(
                Expr::col((CompatSsoLogins::Table, CompatSsoLogins::ExchangedAt)),
                CompatSsoLoginLookupIden::ExchangedAt,
            )
            .from(CompatSsoLogins::Table)
            .apply_filter(filter)
            .generate_pagination(
                (CompatSsoLogins::Table, CompatSsoLogins::CompatSsoLoginId),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<CompatSsoLoginLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(TryFrom::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.compat_sso_login.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err
    )]
    async fn count(&mut self, filter: CompatSsoLoginFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(Expr::col((CompatSsoLogins::Table, CompatSsoLogins::CompatSsoLoginId)).count())
            .from(CompatSsoLogins::Table)
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
}
