// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{AccessToken, AccessTokenState, Clock, Session};
use mas_storage::oauth2::OAuth2AccessTokenRepository;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, tracing::ExecuteExt};

/// An implementation of [`OAuth2AccessTokenRepository`] for a PostgreSQL
/// connection
pub struct PgOAuth2AccessTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2AccessTokenRepository<'c> {
    /// Create a new [`PgOAuth2AccessTokenRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct OAuth2AccessTokenLookup {
    oauth2_access_token_id: Uuid,
    oauth2_session_id: Uuid,
    access_token: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    first_used_at: Option<DateTime<Utc>>,
}

impl From<OAuth2AccessTokenLookup> for AccessToken {
    fn from(value: OAuth2AccessTokenLookup) -> Self {
        let state = match value.revoked_at {
            None => AccessTokenState::Valid,
            Some(revoked_at) => AccessTokenState::Revoked { revoked_at },
        };

        Self {
            id: value.oauth2_access_token_id.into(),
            state,
            session_id: value.oauth2_session_id.into(),
            access_token: value.access_token,
            created_at: value.created_at,
            expires_at: value.expires_at,
            first_used_at: value.first_used_at,
        }
    }
}

#[async_trait]
impl OAuth2AccessTokenRepository for PgOAuth2AccessTokenRepository<'_> {
    type Error = DatabaseError;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<AccessToken>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2AccessTokenLookup,
            r#"
                SELECT oauth2_access_token_id
                     , access_token
                     , created_at
                     , expires_at
                     , revoked_at
                     , oauth2_session_id
                     , first_used_at

                FROM oauth2_access_tokens

                WHERE oauth2_access_token_id = $1
            "#,
            Uuid::from(id),
        )
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.find_by_token",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<AccessToken>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2AccessTokenLookup,
            r#"
                SELECT oauth2_access_token_id
                     , access_token
                     , created_at
                     , expires_at
                     , revoked_at
                     , oauth2_session_id
                     , first_used_at

                FROM oauth2_access_tokens

                WHERE access_token = $1
            "#,
            access_token,
        )
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.add",
        skip_all,
        fields(
            db.query.text,
            %session.id,
            client.id = %session.client_id,
            access_token.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: String,
        expires_after: Option<Duration>,
    ) -> Result<AccessToken, Self::Error> {
        let created_at = clock.now();
        let expires_at = expires_after.map(|d| created_at + d);
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);

        tracing::Span::current().record("access_token.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO oauth2_access_tokens
                    (oauth2_access_token_id, oauth2_session_id, access_token, created_at, expires_at)
                VALUES
                    ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(session.id),
            &access_token,
            created_at,
            expires_at,
        )
            .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(AccessToken {
            id,
            state: AccessTokenState::default(),
            access_token,
            session_id: session.id,
            created_at,
            expires_at,
            first_used_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.revoke",
        skip_all,
        fields(
            db.query.text,
            session.id = %access_token.session_id,
            %access_token.id,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error> {
        let revoked_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_access_tokens
                SET revoked_at = $2
                WHERE oauth2_access_token_id = $1
            "#,
            Uuid::from(access_token.id),
            revoked_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        access_token
            .revoke(revoked_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.mark_used",
        skip_all,
        fields(
            db.query.text,
            session.id = %access_token.session_id,
            %access_token.id,
        ),
        err,
    )]
    async fn mark_used(
        &mut self,
        clock: &dyn Clock,
        mut access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error> {
        let now = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_access_tokens
                SET first_used_at = $2
                WHERE oauth2_access_token_id = $1
            "#,
            Uuid::from(access_token.id),
            now,
        )
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        access_token.first_used_at = Some(now);

        Ok(access_token)
    }

    #[tracing::instrument(
        name = "db.oauth2_access_token.cleanup_revoked",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn cleanup_revoked(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error> {
        // Cleanup token that were revoked more than an hour ago
        let threshold = clock.now() - Duration::microseconds(60 * 60 * 1000 * 1000);
        let res = sqlx::query!(
            r#"
                DELETE FROM oauth2_access_tokens
                WHERE revoked_at < $1
            "#,
            threshold,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(res.rows_affected().try_into().unwrap_or(usize::MAX))
    }
}
