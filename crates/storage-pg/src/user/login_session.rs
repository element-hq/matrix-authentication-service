// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{BrowserSession, Clock, LoginSession, UlidExt as _, User};
use mas_storage::user::LoginSessionRepository;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, ExecuteExt as _};

/// An implementation of [`LoginSessionRepository`] for a PostgreSQL
/// connection
pub struct PgLoginSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgLoginSessionRepository<'c> {
    /// Create a new [`PgLoginSessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct LoginSessionLookup {
    login_session_id: Uuid,
    ip_address: Option<IpAddr>,
    user_agent: Option<String>,
    post_auth_action: Option<serde_json::Value>,
    login_hint: Option<String>,
    target_user_id: Option<Uuid>,
    target_user_session_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    user_session_id: Option<Uuid>,
}

impl From<LoginSessionLookup> for LoginSession {
    fn from(value: LoginSessionLookup) -> Self {
        LoginSession {
            id: value.login_session_id.into(),
            ip_address: value.ip_address,
            user_agent: value.user_agent,
            post_auth_action: value.post_auth_action,
            login_hint: value.login_hint,
            target_user_id: value.target_user_id.map(Into::into),
            target_user_session_id: value.target_user_session_id.map(Into::into),
            created_at: value.created_at,
            completed_at: value.completed_at,
            user_session_id: value.user_session_id.map(Into::into),
        }
    }
}

#[async_trait]
impl LoginSessionRepository for PgLoginSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.login_session.lookup",
        skip_all,
        fields(
            db.query.text,
            login_session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<LoginSession>, Self::Error> {
        let res = sqlx::query_as!(
            LoginSessionLookup,
            r#"
                SELECT login_session_id
                     , ip_address as "ip_address: IpAddr"
                     , user_agent
                     , post_auth_action
                     , login_hint
                     , target_user_id
                     , target_user_session_id
                     , created_at
                     , completed_at
                     , user_session_id
                FROM login_sessions
                WHERE login_session_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        Ok(res.map(Into::into))
    }

    #[tracing::instrument(
        name = "db.login_session.add",
        skip_all,
        fields(
            db.query.text,
            login_session.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        post_auth_action: Option<serde_json::Value>,
        login_hint: Option<String>,
        target_user: Option<&User>,
        target_user_session: Option<&BrowserSession>,
    ) -> Result<LoginSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_rng(created_at, rng);
        tracing::Span::current().record("login_session.id", tracing::field::display(id));

        let target_user_id = target_user.map(|u| u.id);
        let target_user_session_id = target_user_session.map(|s| s.id);

        sqlx::query!(
            r#"
                INSERT INTO login_sessions
                  ( login_session_id
                  , ip_address
                  , user_agent
                  , post_auth_action
                  , login_hint
                  , target_user_id
                  , target_user_session_id
                  , created_at
                  )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            Uuid::from(id),
            ip_address as Option<IpAddr>,
            user_agent.as_deref(),
            post_auth_action,
            login_hint.as_deref(),
            target_user_id.map(Uuid::from),
            target_user_session_id.map(Uuid::from),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(LoginSession {
            id,
            ip_address,
            user_agent,
            post_auth_action,
            login_hint,
            target_user_id,
            target_user_session_id,
            created_at,
            completed_at: None,
            user_session_id: None,
        })
    }

    #[tracing::instrument(
        name = "db.login_session.complete",
        skip_all,
        fields(
            db.query.text,
            login_session.id = %login_session.id,
            user_session.id = %browser_session.id,
        ),
        err,
    )]
    async fn complete(
        &mut self,
        clock: &dyn Clock,
        mut login_session: LoginSession,
        browser_session: &BrowserSession,
    ) -> Result<LoginSession, Self::Error> {
        let completed_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE login_sessions
                SET completed_at = $2, user_session_id = $3
                WHERE login_session_id = $1 AND completed_at IS NULL
            "#,
            Uuid::from(login_session.id),
            completed_at,
            Uuid::from(browser_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        login_session.completed_at = Some(completed_at);
        login_session.user_session_id = Some(browser_session.id);

        Ok(login_session)
    }
}
