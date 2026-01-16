// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    Clock, UpstreamOAuthAuthorizationSession, UpstreamOAuthAuthorizationSessionState,
    UpstreamOAuthLink, UpstreamOAuthProvider,
};
use mas_storage::{
    Page, Pagination,
    pagination::Node,
    upstream_oauth2::{UpstreamOAuthSessionFilter, UpstreamOAuthSessionRepository},
};
use rand::RngCore;
use sea_query::{Expr, PostgresQueryBuilder, Query, enum_def, extension::postgres::PgExpr};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    filter::{Filter, StatementExt},
    iden::UpstreamOAuthAuthorizationSessions,
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

impl Filter for UpstreamOAuthSessionFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.provider().map(|provider| {
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::UpstreamOAuthProviderId,
                ))
                .eq(Uuid::from(provider.id))
            }))
            .add_option(self.sub_claim().map(|sub| {
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::IdTokenClaims,
                ))
                .cast_json_field("sub")
                .eq(sub)
            }))
            .add_option(self.sid_claim().map(|sid| {
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::IdTokenClaims,
                ))
                .cast_json_field("sid")
                .eq(sid)
            }))
    }
}

/// An implementation of [`UpstreamOAuthSessionRepository`] for a PostgreSQL
/// connection
pub struct PgUpstreamOAuthSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUpstreamOAuthSessionRepository<'c> {
    /// Create a new [`PgUpstreamOAuthSessionRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
#[enum_def]
struct SessionLookup {
    upstream_oauth_authorization_session_id: Uuid,
    upstream_oauth_provider_id: Uuid,
    upstream_oauth_link_id: Option<Uuid>,
    state: String,
    code_challenge_verifier: Option<String>,
    nonce: Option<String>,
    id_token: Option<String>,
    id_token_claims: Option<serde_json::Value>,
    userinfo: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
    extra_callback_parameters: Option<serde_json::Value>,
    unlinked_at: Option<DateTime<Utc>>,
}

impl Node<Ulid> for SessionLookup {
    fn cursor(&self) -> Ulid {
        self.upstream_oauth_authorization_session_id.into()
    }
}

impl TryFrom<SessionLookup> for UpstreamOAuthAuthorizationSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: SessionLookup) -> Result<Self, Self::Error> {
        let id = value.upstream_oauth_authorization_session_id.into();
        let state = match (
            value.upstream_oauth_link_id,
            value.id_token,
            value.id_token_claims,
            value.extra_callback_parameters,
            value.userinfo,
            value.completed_at,
            value.consumed_at,
            value.unlinked_at,
        ) {
            (None, None, None, None, None, None, None, None) => {
                UpstreamOAuthAuthorizationSessionState::Pending
            }
            (
                Some(link_id),
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
                Some(completed_at),
                None,
                None,
            ) => UpstreamOAuthAuthorizationSessionState::Completed {
                completed_at,
                link_id: link_id.into(),
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
            },
            (
                Some(link_id),
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
                Some(completed_at),
                Some(consumed_at),
                None,
            ) => UpstreamOAuthAuthorizationSessionState::Consumed {
                completed_at,
                link_id: link_id.into(),
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
                consumed_at,
            },
            (
                _,
                id_token,
                id_token_claims,
                _,
                _,
                Some(completed_at),
                consumed_at,
                Some(unlinked_at),
            ) => UpstreamOAuthAuthorizationSessionState::Unlinked {
                completed_at,
                id_token,
                id_token_claims,
                consumed_at,
                unlinked_at,
            },
            _ => {
                return Err(DatabaseInconsistencyError::on(
                    "upstream_oauth_authorization_sessions",
                )
                .row(id));
            }
        };

        Ok(Self {
            id,
            provider_id: value.upstream_oauth_provider_id.into(),
            state_str: value.state,
            nonce: value.nonce,
            code_challenge_verifier: value.code_challenge_verifier,
            created_at: value.created_at,
            state,
        })
    }
}

#[async_trait]
impl UpstreamOAuthSessionRepository for PgUpstreamOAuthSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.lookup",
        skip_all,
        fields(
            db.query.text,
            upstream_oauth_provider.id = %id,
        ),
        err,
    )]
    async fn lookup(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UpstreamOAuthAuthorizationSession>, Self::Error> {
        let res = sqlx::query_as!(
            SessionLookup,
            r#"
                SELECT
                    upstream_oauth_authorization_session_id,
                    upstream_oauth_provider_id,
                    upstream_oauth_link_id,
                    state,
                    code_challenge_verifier,
                    nonce,
                    id_token,
                    id_token_claims,
                    extra_callback_parameters,
                    userinfo,
                    created_at,
                    completed_at,
                    consumed_at,
                    unlinked_at
                FROM upstream_oauth_authorization_sessions
                WHERE upstream_oauth_authorization_session_id = $1
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
        name = "db.upstream_oauth_authorization_session.add",
        skip_all,
        fields(
            db.query.text,
            %upstream_oauth_provider.id,
            upstream_oauth_provider.issuer = upstream_oauth_provider.issuer,
            %upstream_oauth_provider.client_id,
            upstream_oauth_authorization_session.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        state_str: String,
        code_challenge_verifier: Option<String>,
        nonce: Option<String>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record(
            "upstream_oauth_authorization_session.id",
            tracing::field::display(id),
        );

        sqlx::query!(
            r#"
                INSERT INTO upstream_oauth_authorization_sessions (
                    upstream_oauth_authorization_session_id,
                    upstream_oauth_provider_id,
                    state,
                    code_challenge_verifier,
                    nonce,
                    created_at,
                    completed_at,
                    consumed_at,
                    id_token,
                    userinfo
                ) VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, NULL)
            "#,
            Uuid::from(id),
            Uuid::from(upstream_oauth_provider.id),
            &state_str,
            code_challenge_verifier.as_deref(),
            nonce,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UpstreamOAuthAuthorizationSession {
            id,
            state: UpstreamOAuthAuthorizationSessionState::default(),
            provider_id: upstream_oauth_provider.id,
            state_str,
            code_challenge_verifier,
            nonce,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.complete_with_link",
        skip_all,
        fields(
            db.query.text,
            %upstream_oauth_authorization_session.id,
            %upstream_oauth_link.id,
        ),
        err,
    )]
    async fn complete_with_link(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
        upstream_oauth_link: &UpstreamOAuthLink,
        id_token: Option<String>,
        id_token_claims: Option<serde_json::Value>,
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let completed_at = clock.now();

        sqlx::query!(
            r#"
                UPDATE upstream_oauth_authorization_sessions
                SET upstream_oauth_link_id = $1
                  , completed_at = $2
                  , id_token = $3
                  , id_token_claims = $4
                  , extra_callback_parameters = $5
                  , userinfo = $6
                WHERE upstream_oauth_authorization_session_id = $7
            "#,
            Uuid::from(upstream_oauth_link.id),
            completed_at,
            id_token,
            id_token_claims,
            extra_callback_parameters,
            userinfo,
            Uuid::from(upstream_oauth_authorization_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let upstream_oauth_authorization_session = upstream_oauth_authorization_session
            .complete(
                completed_at,
                upstream_oauth_link,
                id_token,
                id_token_claims,
                extra_callback_parameters,
                userinfo,
            )
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(upstream_oauth_authorization_session)
    }

    /// Mark a session as consumed
    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.consume",
        skip_all,
        fields(
            db.query.text,
            %upstream_oauth_authorization_session.id,
        ),
        err,
    )]
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let consumed_at = clock.now();
        sqlx::query!(
            r#"
                UPDATE upstream_oauth_authorization_sessions
                SET consumed_at = $1
                WHERE upstream_oauth_authorization_session_id = $2
            "#,
            consumed_at,
            Uuid::from(upstream_oauth_authorization_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let upstream_oauth_authorization_session = upstream_oauth_authorization_session
            .consume(consumed_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(upstream_oauth_authorization_session)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: UpstreamOAuthSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthAuthorizationSession>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::UpstreamOAuthAuthorizationSessionId,
                )),
                SessionLookupIden::UpstreamOauthAuthorizationSessionId,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::UpstreamOAuthProviderId,
                )),
                SessionLookupIden::UpstreamOauthProviderId,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::UpstreamOAuthLinkId,
                )),
                SessionLookupIden::UpstreamOauthLinkId,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::State,
                )),
                SessionLookupIden::State,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::CodeChallengeVerifier,
                )),
                SessionLookupIden::CodeChallengeVerifier,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::Nonce,
                )),
                SessionLookupIden::Nonce,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::IdToken,
                )),
                SessionLookupIden::IdToken,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::IdTokenClaims,
                )),
                SessionLookupIden::IdTokenClaims,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::ExtraCallbackParameters,
                )),
                SessionLookupIden::ExtraCallbackParameters,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::Userinfo,
                )),
                SessionLookupIden::Userinfo,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::CreatedAt,
                )),
                SessionLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::CompletedAt,
                )),
                SessionLookupIden::CompletedAt,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::ConsumedAt,
                )),
                SessionLookupIden::ConsumedAt,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::UnlinkedAt,
                )),
                SessionLookupIden::UnlinkedAt,
            )
            .from(UpstreamOAuthAuthorizationSessions::Table)
            .apply_filter(filter)
            .generate_pagination(
                (
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::UpstreamOAuthAuthorizationSessionId,
                ),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<SessionLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination
            .process(edges)
            .try_map(UpstreamOAuthAuthorizationSession::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_authorization_session.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn count(
        &mut self,
        filter: UpstreamOAuthSessionFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(
                Expr::col((
                    UpstreamOAuthAuthorizationSessions::Table,
                    UpstreamOAuthAuthorizationSessions::UpstreamOAuthAuthorizationSessionId,
                ))
                .count(),
            )
            .from(UpstreamOAuthAuthorizationSessions::Table)
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
        name = "db.upstream_oauth_authorization_session.cleanup",
        skip_all,
        fields(
            db.query.text,
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup(
        &mut self,
        since: Option<Ulid>,
        until: Ulid,
        limit: usize,
    ) -> Result<(usize, Option<Ulid>), Self::Error> {
        // Use ULID cursor-based pagination for pending sessions only.
        // We only delete sessions that are not yet completed.
        // `MAX(uuid)` isn't a thing in Postgres, so we aggregate on the client side.
        let res = sqlx::query_scalar!(
            r#"
                WITH to_delete AS (
                    SELECT upstream_oauth_authorization_session_id
                    FROM upstream_oauth_authorization_sessions
                    WHERE ($1::uuid IS NULL OR upstream_oauth_authorization_session_id > $1)
                      AND upstream_oauth_authorization_session_id <= $2
                    ORDER BY upstream_oauth_authorization_session_id
                    LIMIT $3
                )
                DELETE FROM upstream_oauth_authorization_sessions
                USING to_delete
                WHERE upstream_oauth_authorization_sessions.upstream_oauth_authorization_session_id = to_delete.upstream_oauth_authorization_session_id
                RETURNING upstream_oauth_authorization_sessions.upstream_oauth_authorization_session_id
            "#,
            since.map(Uuid::from),
            Uuid::from(until),
            i64::try_from(limit).unwrap_or(i64::MAX)
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        let count = res.len();
        let max_id = res.into_iter().max();

        Ok((count, max_id.map(Ulid::from)))
    }
}
