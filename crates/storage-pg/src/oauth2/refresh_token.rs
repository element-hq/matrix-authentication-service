// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{AccessToken, RefreshToken, RefreshTokenState, Session};
use mas_storage::{Clock, oauth2::OAuth2RefreshTokenRepository};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseInconsistencyError, tracing::ExecuteExt};

/// An implementation of [`OAuth2RefreshTokenRepository`] for a PostgreSQL
/// connection
pub struct PgOAuth2RefreshTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2RefreshTokenRepository<'c> {
    /// Create a new [`PgOAuth2RefreshTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct OAuth2RefreshTokenLookup {
    oauth2_refresh_token_id: Uuid,
    refresh_token: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    oauth2_access_token_id: Option<Uuid>,
    oauth2_session_id: Uuid,
    next_oauth2_refresh_token_id: Option<Uuid>,
}

impl TryFrom<OAuth2RefreshTokenLookup> for RefreshToken {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: OAuth2RefreshTokenLookup) -> Result<Self, Self::Error> {
        let id = value.oauth2_refresh_token_id.into();
        let state = match (
            value.revoked_at,
            value.consumed_at,
            value.next_oauth2_refresh_token_id,
        ) {
            (None, None, None) => RefreshTokenState::Valid,
            (Some(revoked_at), None, None) => RefreshTokenState::Revoked { revoked_at },
            (None, Some(consumed_at), None) => RefreshTokenState::Consumed {
                consumed_at,
                next_refresh_token_id: None,
            },
            (None, Some(consumed_at), Some(id)) => RefreshTokenState::Consumed {
                consumed_at,
                next_refresh_token_id: Some(Ulid::from(id)),
            },
            _ => {
                return Err(DatabaseInconsistencyError::on("oauth2_refresh_tokens")
                    .column("next_oauth2_refresh_token_id")
                    .row(id));
            }
        };

        Ok(RefreshToken {
            id,
            state,
            session_id: value.oauth2_session_id.into(),
            refresh_token: value.refresh_token,
            created_at: value.created_at,
            access_token_id: value.oauth2_access_token_id.map(Ulid::from),
        })
    }
}

#[async_trait]
impl OAuth2RefreshTokenRepository for PgOAuth2RefreshTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.lookup",
        skip_all,
        fields(
            db.query.text,
            refresh_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<RefreshToken>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2RefreshTokenLookup,
            r#"
                SELECT oauth2_refresh_token_id
                     , refresh_token
                     , created_at
                     , consumed_at
                     , revoked_at
                     , oauth2_access_token_id
                     , oauth2_session_id
                     , next_oauth2_refresh_token_id
                FROM oauth2_refresh_tokens

                WHERE oauth2_refresh_token_id = $1
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
        name = "db.oauth2_refresh_token.find_by_token",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2RefreshTokenLookup,
            r#"
                SELECT oauth2_refresh_token_id
                     , refresh_token
                     , created_at
                     , consumed_at
                     , revoked_at
                     , oauth2_access_token_id
                     , oauth2_session_id
                     , next_oauth2_refresh_token_id
                FROM oauth2_refresh_tokens

                WHERE refresh_token = $1
            "#,
            refresh_token,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.add",
        skip_all,
        fields(
            db.query.text,
            %session.id,
            client.id = %session.client_id,
            refresh_token.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: &AccessToken,
        refresh_token: String,
    ) -> Result<RefreshToken, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("refresh_token.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO oauth2_refresh_tokens
                    (oauth2_refresh_token_id, oauth2_session_id, oauth2_access_token_id,
                     refresh_token, created_at)
                VALUES
                    ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            Uuid::from(session.id),
            Uuid::from(access_token.id),
            refresh_token,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(RefreshToken {
            id,
            state: RefreshTokenState::default(),
            session_id: session.id,
            refresh_token,
            access_token_id: Some(access_token.id),
            created_at,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.consume",
        skip_all,
        fields(
            db.query.text,
            %refresh_token.id,
            session.id = %refresh_token.session_id,
        ),
        err,
    )]
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
        replaced_by: &RefreshToken,
    ) -> Result<RefreshToken, Self::Error> {
        let consumed_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_refresh_tokens
                SET consumed_at = $2,
                    next_oauth2_refresh_token_id = $3
                WHERE oauth2_refresh_token_id = $1
            "#,
            Uuid::from(refresh_token.id),
            consumed_at,
            Uuid::from(replaced_by.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        refresh_token
            .consume(consumed_at, replaced_by)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.oauth2_refresh_token.revoke",
        skip_all,
        fields(
            db.query.text,
            %refresh_token.id,
            session.id = %refresh_token.session_id,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
    ) -> Result<RefreshToken, Self::Error> {
        let revoked_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_refresh_tokens
                SET revoked_at = $2
                WHERE oauth2_refresh_token_id = $1
            "#,
            Uuid::from(refresh_token.id),
            revoked_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        refresh_token
            .revoke(revoked_at)
            .map_err(DatabaseError::to_invalid_operation)
    }
}
