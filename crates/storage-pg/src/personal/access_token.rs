// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    Clock,
    personal::{PersonalAccessToken, session::PersonalSession},
};
use mas_storage::personal::PersonalAccessTokenRepository;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, tracing::ExecuteExt as _};

/// An implementation of [`PersonalAccessTokenRepository`] for a PostgreSQL
/// connection
pub struct PgPersonalAccessTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgPersonalAccessTokenRepository<'c> {
    /// Create a new [`PgPersonalAccessTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct PersonalAccessTokenLookup {
    personal_access_token_id: Uuid,
    personal_session_id: Uuid,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<PersonalAccessTokenLookup> for PersonalAccessToken {
    fn from(value: PersonalAccessTokenLookup) -> Self {
        Self {
            id: Ulid::from(value.personal_access_token_id),
            session_id: Ulid::from(value.personal_session_id),
            created_at: value.created_at,
            expires_at: value.expires_at,
            revoked_at: value.revoked_at,
        }
    }
}

#[async_trait]
impl PersonalAccessTokenRepository for PgPersonalAccessTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.personal_access_token.lookup",
        skip_all,
        fields(
            db.query.text,
            personal_access_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalAccessToken>, Self::Error> {
        let res = sqlx::query_as!(
            PersonalAccessTokenLookup,
            r#"
                SELECT personal_access_token_id
                     , personal_session_id
                     , created_at
                     , expires_at
                     , revoked_at

                FROM personal_access_tokens

                WHERE personal_access_token_id = $1
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
        name = "db.personal_access_token.find_by_token",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<PersonalAccessToken>, Self::Error> {
        let token_sha256 = Sha256::digest(access_token.as_bytes()).to_vec();

        let res = sqlx::query_as!(
            PersonalAccessTokenLookup,
            r#"
                SELECT personal_access_token_id
                     , personal_session_id
                     , created_at
                     , expires_at
                     , revoked_at

                FROM personal_access_tokens

                WHERE access_token_sha256 = $1
            "#,
            &token_sha256,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.into()))
    }

    #[tracing::instrument(
        name = "db.personal_access_token.add",
        skip_all,
        fields(
            db.query.text,
            personal_access_token.id,
            %session.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &PersonalSession,
        access_token: &str,
        expires_after: Option<chrono::Duration>,
    ) -> Result<PersonalAccessToken, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("personal_access_token.id", tracing::field::display(id));

        let token_sha256 = Sha256::digest(access_token.as_bytes()).to_vec();

        let expires_at = expires_after.map(|expires_after| created_at + expires_after);

        sqlx::query!(
            r#"
                INSERT INTO personal_access_tokens
                    (personal_access_token_id, personal_session_id, access_token_sha256, created_at, expires_at)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(session.id),
            &token_sha256,
            created_at,
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(PersonalAccessToken {
            id,
            session_id: session.id,
            created_at,
            expires_at,
            revoked_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.personal_access_token.revoke",
        skip_all,
        fields(
            db.query.text,
            %access_token.id,
            personal_session.id = %access_token.session_id,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        mut access_token: PersonalAccessToken,
    ) -> Result<PersonalAccessToken, Self::Error> {
        let revoked_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE personal_access_tokens
                SET revoked_at = $2
                WHERE personal_access_token_id = $1
            "#,
            Uuid::from(access_token.id),
            revoked_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        access_token.revoked_at = Some(revoked_at);
        Ok(access_token)
    }
}
