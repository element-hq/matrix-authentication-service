// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    UpstreamOAuthAuthorizationSession, UpstreamOAuthAuthorizationSessionState, UpstreamOAuthLink,
    UpstreamOAuthProvider,
};
use mas_storage::{upstream_oauth2::UpstreamOAuthSessionRepository, Clock};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{tracing::ExecuteExt, DatabaseError, DatabaseInconsistencyError};

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

struct SessionLookup {
    upstream_oauth_authorization_session_id: Uuid,
    upstream_oauth_provider_id: Uuid,
    upstream_oauth_link_id: Option<Uuid>,
    state: String,
    code_challenge_verifier: Option<String>,
    nonce: String,
    id_token: Option<String>,
    userinfo: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
    extra_callback_parameters: Option<serde_json::Value>,
}

impl TryFrom<SessionLookup> for UpstreamOAuthAuthorizationSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: SessionLookup) -> Result<Self, Self::Error> {
        let id = value.upstream_oauth_authorization_session_id.into();
        let state = match (
            value.upstream_oauth_link_id,
            value.id_token,
            value.extra_callback_parameters,
            value.userinfo,
            value.completed_at,
            value.consumed_at,
        ) {
            (None, None, None, None, None, None) => UpstreamOAuthAuthorizationSessionState::Pending,
            (
                Some(link_id),
                id_token,
                extra_callback_parameters,
                userinfo,
                Some(completed_at),
                None,
            ) => UpstreamOAuthAuthorizationSessionState::Completed {
                completed_at,
                link_id: link_id.into(),
                id_token,
                extra_callback_parameters,
                userinfo,
            },
            (
                Some(link_id),
                id_token,
                extra_callback_parameters,
                userinfo,
                Some(completed_at),
                Some(consumed_at),
            ) => UpstreamOAuthAuthorizationSessionState::Consumed {
                completed_at,
                link_id: link_id.into(),
                id_token,
                extra_callback_parameters,
                userinfo,
                consumed_at,
            },
            _ => {
                return Err(
                    DatabaseInconsistencyError::on("upstream_oauth_authorization_sessions").row(id),
                )
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
impl<'c> UpstreamOAuthSessionRepository for PgUpstreamOAuthSessionRepository<'c> {
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
                    extra_callback_parameters,
                    userinfo,
                    created_at,
                    completed_at,
                    consumed_at
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
            %upstream_oauth_provider.issuer,
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
        nonce: String,
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
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error> {
        let completed_at = clock.now();

        sqlx::query!(
            r#"
                UPDATE upstream_oauth_authorization_sessions
                SET upstream_oauth_link_id = $1,
                    completed_at = $2,
                    id_token = $3,
                    extra_callback_parameters = $4,
                    userinfo = $5
                WHERE upstream_oauth_authorization_session_id = $6
            "#,
            Uuid::from(upstream_oauth_link.id),
            completed_at,
            id_token,
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
}
