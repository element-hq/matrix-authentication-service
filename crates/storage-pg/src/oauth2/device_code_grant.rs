// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{BrowserSession, Clock, DeviceCodeGrant, DeviceCodeGrantState, Session};
use mas_storage::oauth2::{OAuth2DeviceCodeGrantParams, OAuth2DeviceCodeGrantRepository};
use oauth2_types::scope::Scope;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, ExecuteExt, errors::DatabaseInconsistencyError};

/// An implementation of [`OAuth2DeviceCodeGrantRepository`] for a PostgreSQL
/// connection
pub struct PgOAuth2DeviceCodeGrantRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2DeviceCodeGrantRepository<'c> {
    /// Create a new [`PgOAuth2DeviceCodeGrantRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct OAuth2DeviceGrantLookup {
    oauth2_device_code_grant_id: Uuid,
    oauth2_client_id: Uuid,
    scope: String,
    device_code: String,
    user_code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    fulfilled_at: Option<DateTime<Utc>>,
    rejected_at: Option<DateTime<Utc>>,
    exchanged_at: Option<DateTime<Utc>>,
    user_session_id: Option<Uuid>,
    oauth2_session_id: Option<Uuid>,
    ip_address: Option<IpAddr>,
    user_agent: Option<String>,
}

impl TryFrom<OAuth2DeviceGrantLookup> for DeviceCodeGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(
        OAuth2DeviceGrantLookup {
            oauth2_device_code_grant_id,
            oauth2_client_id,
            scope,
            device_code,
            user_code,
            created_at,
            expires_at,
            fulfilled_at,
            rejected_at,
            exchanged_at,
            user_session_id,
            oauth2_session_id,
            ip_address,
            user_agent,
        }: OAuth2DeviceGrantLookup,
    ) -> Result<Self, Self::Error> {
        let id = Ulid::from(oauth2_device_code_grant_id);
        let client_id = Ulid::from(oauth2_client_id);

        let scope: Scope = scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_authorization_grants")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match (
            fulfilled_at,
            rejected_at,
            exchanged_at,
            user_session_id,
            oauth2_session_id,
        ) {
            (None, None, None, None, None) => DeviceCodeGrantState::Pending,

            (Some(fulfilled_at), None, None, Some(user_session_id), None) => {
                DeviceCodeGrantState::Fulfilled {
                    browser_session_id: Ulid::from(user_session_id),
                    fulfilled_at,
                }
            }

            (None, Some(rejected_at), None, Some(user_session_id), None) => {
                DeviceCodeGrantState::Rejected {
                    browser_session_id: Ulid::from(user_session_id),
                    rejected_at,
                }
            }

            (
                Some(fulfilled_at),
                None,
                Some(exchanged_at),
                Some(user_session_id),
                Some(oauth2_session_id),
            ) => DeviceCodeGrantState::Exchanged {
                browser_session_id: Ulid::from(user_session_id),
                session_id: Ulid::from(oauth2_session_id),
                fulfilled_at,
                exchanged_at,
            },

            _ => return Err(DatabaseInconsistencyError::on("oauth2_device_code_grant").row(id)),
        };

        Ok(DeviceCodeGrant {
            id,
            state,
            client_id,
            scope,
            user_code,
            device_code,
            created_at,
            expires_at,
            ip_address,
            user_agent,
        })
    }
}

#[async_trait]
impl OAuth2DeviceCodeGrantRepository for PgOAuth2DeviceCodeGrantRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.add",
        skip_all,
        fields(
            db.query.text,
            oauth2_device_code.id,
            oauth2_device_code.scope = %params.scope,
            oauth2_client.id = %params.client.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: OAuth2DeviceCodeGrantParams<'_>,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let now = clock.now();
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        tracing::Span::current().record("oauth2_device_code.id", tracing::field::display(id));

        let created_at = now;
        let expires_at = now + params.expires_in;
        let client_id = params.client.id;

        sqlx::query!(
            r#"
                INSERT INTO "oauth2_device_code_grant"
                    ( oauth2_device_code_grant_id
                    , oauth2_client_id
                    , scope
                    , device_code
                    , user_code
                    , created_at
                    , expires_at
                    , ip_address
                    , user_agent
                    )
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            Uuid::from(id),
            Uuid::from(client_id),
            params.scope.to_string(),
            &params.device_code,
            &params.user_code,
            created_at,
            expires_at,
            params.ip_address as Option<IpAddr>,
            params.user_agent.as_deref(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(DeviceCodeGrant {
            id,
            state: DeviceCodeGrantState::Pending,
            client_id,
            scope: params.scope,
            user_code: params.user_code,
            device_code: params.device_code,
            created_at,
            expires_at,
            ip_address: params.ip_address,
            user_agent: params.user_agent,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.lookup",
        skip_all,
        fields(
            db.query.text,
            oauth2_device_code.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<DeviceCodeGrant>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2DeviceGrantLookup,
            r#"
                SELECT oauth2_device_code_grant_id
                     , oauth2_client_id
                     , scope
                     , device_code
                     , user_code
                     , created_at
                     , expires_at
                     , fulfilled_at
                     , rejected_at
                     , exchanged_at
                     , user_session_id
                     , oauth2_session_id
                     , ip_address as "ip_address: IpAddr"
                     , user_agent
                FROM
                    oauth2_device_code_grant

                WHERE oauth2_device_code_grant_id = $1
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
        name = "db.oauth2_device_code_grant.find_by_user_code",
        skip_all,
        fields(
            db.query.text,
            oauth2_device_code.user_code = %user_code,
        ),
        err,
    )]
    async fn find_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2DeviceGrantLookup,
            r#"
                SELECT oauth2_device_code_grant_id
                     , oauth2_client_id
                     , scope
                     , device_code
                     , user_code
                     , created_at
                     , expires_at
                     , fulfilled_at
                     , rejected_at
                     , exchanged_at
                     , user_session_id
                     , oauth2_session_id
                     , ip_address as "ip_address: IpAddr"
                     , user_agent
                FROM
                    oauth2_device_code_grant

                WHERE user_code = $1
            "#,
            user_code,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.find_by_device_code",
        skip_all,
        fields(
            db.query.text,
            oauth2_device_code.device_code = %device_code,
        ),
        err,
    )]
    async fn find_by_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2DeviceGrantLookup,
            r#"
                SELECT oauth2_device_code_grant_id
                     , oauth2_client_id
                     , scope
                     , device_code
                     , user_code
                     , created_at
                     , expires_at
                     , fulfilled_at
                     , rejected_at
                     , exchanged_at
                     , user_session_id
                     , oauth2_session_id
                     , ip_address as "ip_address: IpAddr"
                     , user_agent
                FROM
                    oauth2_device_code_grant

                WHERE device_code = $1
            "#,
            device_code,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.fulfill",
        skip_all,
        fields(
            db.query.text,
            oauth2_device_code.id = %device_code_grant.id,
            oauth2_client.id = %device_code_grant.client_id,
            browser_session.id = %browser_session.id,
            user.id = %browser_session.user.id,
        ),
        err,
    )]
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let fulfilled_at = clock.now();
        let device_code_grant = device_code_grant
            .fulfill(browser_session, fulfilled_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE oauth2_device_code_grant
                SET fulfilled_at = $1
                  , user_session_id = $2
                WHERE oauth2_device_code_grant_id = $3
            "#,
            fulfilled_at,
            Uuid::from(browser_session.id),
            Uuid::from(device_code_grant.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(device_code_grant)
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.reject",
        skip_all,
        fields(
            db.query.text,
            oauth2_device_code.id = %device_code_grant.id,
            oauth2_client.id = %device_code_grant.client_id,
            browser_session.id = %browser_session.id,
            user.id = %browser_session.user.id,
        ),
        err,
    )]
    async fn reject(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        browser_session: &BrowserSession,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let fulfilled_at = clock.now();
        let device_code_grant = device_code_grant
            .reject(browser_session, fulfilled_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE oauth2_device_code_grant
                SET rejected_at = $1
                  , user_session_id = $2
                WHERE oauth2_device_code_grant_id = $3
            "#,
            fulfilled_at,
            Uuid::from(browser_session.id),
            Uuid::from(device_code_grant.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(device_code_grant)
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.exchange",
        skip_all,
        fields(
            db.query.text,
            oauth2_device_code.id = %device_code_grant.id,
            oauth2_client.id = %device_code_grant.client_id,
            oauth2_session.id = %session.id,
        ),
        err,
    )]
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        device_code_grant: DeviceCodeGrant,
        session: &Session,
    ) -> Result<DeviceCodeGrant, Self::Error> {
        let exchanged_at = clock.now();
        let device_code_grant = device_code_grant
            .exchange(session, exchanged_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        let res = sqlx::query!(
            r#"
                UPDATE oauth2_device_code_grant
                SET exchanged_at = $1
                  , oauth2_session_id = $2
                WHERE oauth2_device_code_grant_id = $3
            "#,
            exchanged_at,
            Uuid::from(session.id),
            Uuid::from(device_code_grant.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(device_code_grant)
    }

    #[tracing::instrument(
        name = "db.oauth2_device_code_grant.cleanup",
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
        // `MAX(uuid)` isn't a thing in Postgres, so we can't just re-select the
        // deleted rows and do a MAX on the `oauth2_device_code_grant_id`.
        // Instead, we do the aggregation on the client side, which is a little
        // less efficient, but good enough.
        let res = sqlx::query_scalar!(
            r#"
                WITH to_delete AS (
                    SELECT oauth2_device_code_grant_id
                    FROM oauth2_device_code_grant
                    WHERE ($1::uuid IS NULL OR oauth2_device_code_grant_id > $1)
                    AND oauth2_device_code_grant_id <= $2
                    ORDER BY oauth2_device_code_grant_id
                    LIMIT $3
                )
                DELETE FROM oauth2_device_code_grant
                USING to_delete
                WHERE oauth2_device_code_grant.oauth2_device_code_grant_id = to_delete.oauth2_device_code_grant_id
                RETURNING oauth2_device_code_grant.oauth2_device_code_grant_id
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
