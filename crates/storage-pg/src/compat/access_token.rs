// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{Clock, CompatAccessToken, CompatSession};
use mas_storage::compat::CompatAccessTokenRepository;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, tracing::ExecuteExt};

/// An implementation of [`CompatAccessTokenRepository`] for a PostgreSQL
/// connection
pub struct PgCompatAccessTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgCompatAccessTokenRepository<'c> {
    /// Create a new [`PgCompatAccessTokenRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct CompatAccessTokenLookup {
    compat_access_token_id: Uuid,
    access_token: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    compat_session_id: Uuid,
}

impl From<CompatAccessTokenLookup> for CompatAccessToken {
    fn from(value: CompatAccessTokenLookup) -> Self {
        Self {
            id: value.compat_access_token_id.into(),
            session_id: value.compat_session_id.into(),
            token: value.access_token,
            created_at: value.created_at,
            expires_at: value.expires_at,
        }
    }
}

#[async_trait]
impl CompatAccessTokenRepository for PgCompatAccessTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.compat_access_token.lookup",
        skip_all,
        fields(
            db.query.text,
            compat_session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatAccessToken>, Self::Error> {
        let res = sqlx::query_as!(
            CompatAccessTokenLookup,
            r#"
                SELECT compat_access_token_id
                     , access_token
                     , created_at
                     , expires_at
                     , compat_session_id

                FROM compat_access_tokens

                WHERE compat_access_token_id = $1
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
        name = "db.compat_access_token.find_by_token",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<CompatAccessToken>, Self::Error> {
        let res = sqlx::query_as!(
            CompatAccessTokenLookup,
            r#"
                SELECT compat_access_token_id
                     , access_token
                     , created_at
                     , expires_at
                     , compat_session_id

                FROM compat_access_tokens

                WHERE access_token = $1
            "#,
            access_token,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.compat_access_token.add",
        skip_all,
        fields(
            db.query.text,
            compat_access_token.id,
            %compat_session.id,
            user.id = %compat_session.user_id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        compat_session: &CompatSession,
        token: String,
        expires_after: Option<Duration>,
    ) -> Result<CompatAccessToken, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("compat_access_token.id", tracing::field::display(id));

        let expires_at = expires_after.map(|expires_after| created_at + expires_after);

        sqlx::query!(
            r#"
                INSERT INTO compat_access_tokens
                    (compat_access_token_id, compat_session_id, access_token, created_at, expires_at)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(compat_session.id),
            token,
            created_at,
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(CompatAccessToken {
            id,
            session_id: compat_session.id,
            token,
            created_at,
            expires_at,
        })
    }

    #[tracing::instrument(
        name = "db.compat_access_token.expire",
        skip_all,
        fields(
            db.query.text,
            %compat_access_token.id,
            compat_session.id = %compat_access_token.session_id,
        ),
        err,
    )]
    async fn expire(
        &mut self,
        clock: &dyn Clock,
        mut compat_access_token: CompatAccessToken,
    ) -> Result<CompatAccessToken, Self::Error> {
        let expires_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE compat_access_tokens
                SET expires_at = $2
                WHERE compat_access_token_id = $1
            "#,
            Uuid::from(compat_access_token.id),
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        compat_access_token.expires_at = Some(expires_at);
        Ok(compat_access_token)
    }
}
