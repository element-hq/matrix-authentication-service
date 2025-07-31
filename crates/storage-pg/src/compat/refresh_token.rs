// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    Clock, CompatAccessToken, CompatRefreshToken, CompatRefreshTokenState, CompatSession,
};
use mas_storage::compat::CompatRefreshTokenRepository;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, tracing::ExecuteExt};

/// An implementation of [`CompatRefreshTokenRepository`] for a PostgreSQL
/// connection
pub struct PgCompatRefreshTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgCompatRefreshTokenRepository<'c> {
    /// Create a new [`PgCompatRefreshTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct CompatRefreshTokenLookup {
    compat_refresh_token_id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    compat_access_token_id: Uuid,
    compat_session_id: Uuid,
}

impl From<CompatRefreshTokenLookup> for CompatRefreshToken {
    fn from(value: CompatRefreshTokenLookup) -> Self {
        let state = match value.consumed_at {
            Some(consumed_at) => CompatRefreshTokenState::Consumed { consumed_at },
            None => CompatRefreshTokenState::Valid,
        };

        Self {
            id: value.compat_refresh_token_id.into(),
            state,
            session_id: value.compat_session_id.into(),
            token: value.refresh_token,
            created_at: value.created_at,
            access_token_id: value.compat_access_token_id.into(),
        }
    }
}

#[async_trait]
impl CompatRefreshTokenRepository for PgCompatRefreshTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.compat_refresh_token.lookup",
        skip_all,
        fields(
            db.query.text,
            compat_refresh_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatRefreshToken>, Self::Error> {
        let res = sqlx::query_as!(
            CompatRefreshTokenLookup,
            r#"
                SELECT compat_refresh_token_id
                     , refresh_token
                     , created_at
                     , consumed_at
                     , compat_session_id
                     , compat_access_token_id

                FROM compat_refresh_tokens

                WHERE compat_refresh_token_id = $1
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
        name = "db.compat_refresh_token.find_by_token",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<CompatRefreshToken>, Self::Error> {
        let res = sqlx::query_as!(
            CompatRefreshTokenLookup,
            r#"
                SELECT compat_refresh_token_id
                     , refresh_token
                     , created_at
                     , consumed_at
                     , compat_session_id
                     , compat_access_token_id

                FROM compat_refresh_tokens

                WHERE refresh_token = $1
            "#,
            refresh_token,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.compat_refresh_token.add",
        skip_all,
        fields(
            db.query.text,
            compat_refresh_token.id,
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
        compat_access_token: &CompatAccessToken,
        token: String,
    ) -> Result<CompatRefreshToken, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("compat_refresh_token.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO compat_refresh_tokens
                    (compat_refresh_token_id, compat_session_id,
                     compat_access_token_id, refresh_token, created_at)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(compat_session.id),
            Uuid::from(compat_access_token.id),
            token,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(CompatRefreshToken {
            id,
            state: CompatRefreshTokenState::default(),
            session_id: compat_session.id,
            access_token_id: compat_access_token.id,
            token,
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.compat_refresh_token.consume",
        skip_all,
        fields(
            db.query.text,
            %compat_refresh_token.id,
            compat_session.id = %compat_refresh_token.session_id,
        ),
        err,
    )]
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        compat_refresh_token: CompatRefreshToken,
    ) -> Result<CompatRefreshToken, Self::Error> {
        let consumed_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE compat_refresh_tokens
                SET consumed_at = $2
                WHERE compat_session_id = $1
                  AND consumed_at IS NULL
            "#,
            Uuid::from(compat_refresh_token.session_id),
            consumed_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        // This can affect multiple rows in case we've imported refresh tokens
        // from Synapse. What we care about is that it at least affected one,
        // which is what we're checking here
        if res.rows_affected() == 0 {
            return Err(DatabaseError::RowsAffected {
                expected: 1,
                actual: 0,
            });
        }

        let compat_refresh_token = compat_refresh_token
            .consume(consumed_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(compat_refresh_token)
    }
}
