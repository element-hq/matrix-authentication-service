// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{Clock, UpstreamOAuthLink, UpstreamOAuthLinkToken};
use mas_storage::upstream_oauth2::UpstreamOAuthLinkTokenRepository;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, tracing::ExecuteExt};

/// An implementation of [`UpstreamOAuthLinkTokenRepository`] for a PostgreSQL
/// connection
pub struct PgUpstreamOAuthLinkTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUpstreamOAuthLinkTokenRepository<'c> {
    /// Create a new [`PgUpstreamOAuthLinkTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
struct LinkTokenLookup {
    upstream_oauth_link_token_id: Uuid,
    upstream_oauth_link_id: Uuid,
    encrypted_access_token: String,
    encrypted_refresh_token: Option<String>,
    access_token_expires_at: Option<DateTime<Utc>>,
    token_scope: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<LinkTokenLookup> for UpstreamOAuthLinkToken {
    fn from(value: LinkTokenLookup) -> Self {
        UpstreamOAuthLinkToken {
            id: Ulid::from(value.upstream_oauth_link_token_id),
            link_id: Ulid::from(value.upstream_oauth_link_id),
            encrypted_access_token: value.encrypted_access_token,
            encrypted_refresh_token: value.encrypted_refresh_token,
            access_token_expires_at: value.access_token_expires_at,
            token_scope: value.token_scope,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[async_trait]
impl UpstreamOAuthLinkTokenRepository for PgUpstreamOAuthLinkTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.upstream_oauth_link_token.lookup",
        skip_all,
        fields(
            db.query.text,
            upstream_oauth_link_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthLinkToken>, Self::Error> {
        let res = sqlx::query_as!(
            LinkTokenLookup,
            r#"
                SELECT
                    upstream_oauth_link_token_id,
                    upstream_oauth_link_id,
                    encrypted_access_token,
                    encrypted_refresh_token,
                    access_token_expires_at,
                    token_scope,
                    created_at,
                    updated_at
                FROM upstream_oauth_link_tokens
                WHERE upstream_oauth_link_token_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?
        .map(Into::into);

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link_token.find_by_link",
        skip_all,
        fields(
            db.query.text,
            %upstream_oauth_link.id,
        ),
        err,
    )]
    async fn find_by_link(
        &mut self,
        upstream_oauth_link: &UpstreamOAuthLink,
    ) -> Result<Option<UpstreamOAuthLinkToken>, Self::Error> {
        let res = sqlx::query_as!(
            LinkTokenLookup,
            r#"
                SELECT
                    upstream_oauth_link_token_id,
                    upstream_oauth_link_id,
                    encrypted_access_token,
                    encrypted_refresh_token,
                    access_token_expires_at,
                    token_scope,
                    created_at,
                    updated_at
                FROM upstream_oauth_link_tokens
                WHERE upstream_oauth_link_id = $1
            "#,
            Uuid::from(upstream_oauth_link.id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?
        .map(Into::into);

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link_token.add",
        skip_all,
        fields(
            db.query.text,
            upstream_oauth_link_token.id,
            %upstream_oauth_link.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        upstream_oauth_link: &UpstreamOAuthLink,
        encrypted_access_token: String,
        encrypted_refresh_token: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        scope: Option<String>,
    ) -> Result<UpstreamOAuthLinkToken, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current()
            .record("upstream_oauth_link_token.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO upstream_oauth_link_tokens (
                    upstream_oauth_link_token_id,
                    upstream_oauth_link_id,
                    encrypted_access_token,
                    encrypted_refresh_token,
                    access_token_expires_at,
                    token_scope,
                    created_at,
                    updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
            "#,
            Uuid::from(id),
            Uuid::from(upstream_oauth_link.id),
            &encrypted_access_token,
            encrypted_refresh_token.as_deref(),
            expires_at,
            scope.as_deref(),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UpstreamOAuthLinkToken {
            id,
            link_id: upstream_oauth_link.id,
            encrypted_access_token,
            encrypted_refresh_token,
            access_token_expires_at: expires_at,
            token_scope: scope,
            created_at,
            updated_at: created_at,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_link_token.update_tokens",
        skip_all,
        fields(
            db.query.text,
            %link_token.id,
            %link_token.link_id,
        ),
        err,
    )]
    async fn update_tokens(
        &mut self,
        clock: &dyn Clock,
        link_token: UpstreamOAuthLinkToken,
        encrypted_access_token: String,
        encrypted_refresh_token: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UpstreamOAuthLinkToken, Self::Error> {
        let updated_at = clock.now();

        sqlx::query!(
            r#"
                UPDATE upstream_oauth_link_tokens
                SET
                    encrypted_access_token = $2,
                    encrypted_refresh_token = $3,
                    access_token_expires_at = $4,
                    updated_at = $5
                WHERE upstream_oauth_link_token_id = $1
            "#,
            Uuid::from(link_token.id),
            &encrypted_access_token,
            encrypted_refresh_token.as_deref(),
            expires_at,
            updated_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UpstreamOAuthLinkToken {
            encrypted_access_token,
            encrypted_refresh_token,
            access_token_expires_at: expires_at,
            updated_at,
            ..link_token
        })
    }
}
