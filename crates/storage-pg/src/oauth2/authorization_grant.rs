// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, Client, Pkce, Session,
};
use mas_iana::oauth::PkceCodeChallengeMethod;
use mas_storage::{Clock, oauth2::OAuth2AuthorizationGrantRepository};
use oauth2_types::{requests::ResponseMode, scope::Scope};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseInconsistencyError, tracing::ExecuteExt};

/// An implementation of [`OAuth2AuthorizationGrantRepository`] for a PostgreSQL
/// connection
pub struct PgOAuth2AuthorizationGrantRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2AuthorizationGrantRepository<'c> {
    /// Create a new [`PgOAuth2AuthorizationGrantRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[allow(clippy::struct_excessive_bools)]
struct GrantLookup {
    oauth2_authorization_grant_id: Uuid,
    created_at: DateTime<Utc>,
    cancelled_at: Option<DateTime<Utc>>,
    fulfilled_at: Option<DateTime<Utc>>,
    exchanged_at: Option<DateTime<Utc>>,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    redirect_uri: String,
    response_mode: String,
    response_type_code: bool,
    response_type_id_token: bool,
    authorization_code: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    login_hint: Option<String>,
    oauth2_client_id: Uuid,
    oauth2_session_id: Option<Uuid>,
}

impl TryFrom<GrantLookup> for AuthorizationGrant {
    type Error = DatabaseInconsistencyError;

    #[allow(clippy::too_many_lines)]
    fn try_from(value: GrantLookup) -> Result<Self, Self::Error> {
        let id = value.oauth2_authorization_grant_id.into();
        let scope: Scope = value.scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_authorization_grants")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let stage = match (
            value.fulfilled_at,
            value.exchanged_at,
            value.cancelled_at,
            value.oauth2_session_id,
        ) {
            (None, None, None, None) => AuthorizationGrantStage::Pending,
            (Some(fulfilled_at), None, None, Some(session_id)) => {
                AuthorizationGrantStage::Fulfilled {
                    session_id: session_id.into(),
                    fulfilled_at,
                }
            }
            (Some(fulfilled_at), Some(exchanged_at), None, Some(session_id)) => {
                AuthorizationGrantStage::Exchanged {
                    session_id: session_id.into(),
                    fulfilled_at,
                    exchanged_at,
                }
            }
            (None, None, Some(cancelled_at), None) => {
                AuthorizationGrantStage::Cancelled { cancelled_at }
            }
            _ => {
                return Err(
                    DatabaseInconsistencyError::on("oauth2_authorization_grants")
                        .column("stage")
                        .row(id),
                );
            }
        };

        let pkce = match (value.code_challenge, value.code_challenge_method) {
            (Some(challenge), Some(challenge_method)) if challenge_method == "plain" => {
                Some(Pkce {
                    challenge_method: PkceCodeChallengeMethod::Plain,
                    challenge,
                })
            }
            (Some(challenge), Some(challenge_method)) if challenge_method == "S256" => Some(Pkce {
                challenge_method: PkceCodeChallengeMethod::S256,
                challenge,
            }),
            (None, None) => None,
            _ => {
                return Err(
                    DatabaseInconsistencyError::on("oauth2_authorization_grants")
                        .column("code_challenge_method")
                        .row(id),
                );
            }
        };

        let code: Option<AuthorizationCode> =
            match (value.response_type_code, value.authorization_code, pkce) {
                (false, None, None) => None,
                (true, Some(code), pkce) => Some(AuthorizationCode { code, pkce }),
                _ => {
                    return Err(
                        DatabaseInconsistencyError::on("oauth2_authorization_grants")
                            .column("authorization_code")
                            .row(id),
                    );
                }
            };

        let redirect_uri = value.redirect_uri.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_authorization_grants")
                .column("redirect_uri")
                .row(id)
                .source(e)
        })?;

        let response_mode = value.response_mode.parse().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_authorization_grants")
                .column("response_mode")
                .row(id)
                .source(e)
        })?;

        Ok(AuthorizationGrant {
            id,
            stage,
            client_id: value.oauth2_client_id.into(),
            code,
            scope,
            state: value.state,
            nonce: value.nonce,
            response_mode,
            redirect_uri,
            created_at: value.created_at,
            response_type_id_token: value.response_type_id_token,
            login_hint: value.login_hint,
        })
    }
}

#[async_trait]
impl OAuth2AuthorizationGrantRepository for PgOAuth2AuthorizationGrantRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_authorization_grant.add",
        skip_all,
        fields(
            db.query.text,
            grant.id,
            grant.scope = %scope,
            %client.id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        redirect_uri: Url,
        scope: Scope,
        code: Option<AuthorizationCode>,
        state: Option<String>,
        nonce: Option<String>,
        response_mode: ResponseMode,
        response_type_id_token: bool,
        login_hint: Option<String>,
    ) -> Result<AuthorizationGrant, Self::Error> {
        let code_challenge = code
            .as_ref()
            .and_then(|c| c.pkce.as_ref())
            .map(|p| &p.challenge);
        let code_challenge_method = code
            .as_ref()
            .and_then(|c| c.pkce.as_ref())
            .map(|p| p.challenge_method.to_string());
        let code_str = code.as_ref().map(|c| &c.code);

        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("grant.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO oauth2_authorization_grants (
                     oauth2_authorization_grant_id,
                     oauth2_client_id,
                     redirect_uri,
                     scope,
                     state,
                     nonce,
                     response_mode,
                     code_challenge,
                     code_challenge_method,
                     response_type_code,
                     response_type_id_token,
                     authorization_code,
                     login_hint,
                     created_at
                )
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
            Uuid::from(id),
            Uuid::from(client.id),
            redirect_uri.to_string(),
            scope.to_string(),
            state,
            nonce,
            response_mode.to_string(),
            code_challenge,
            code_challenge_method,
            code.is_some(),
            response_type_id_token,
            code_str,
            login_hint,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(AuthorizationGrant {
            id,
            stage: AuthorizationGrantStage::Pending,
            code,
            redirect_uri,
            client_id: client.id,
            scope,
            state,
            nonce,
            response_mode,
            created_at,
            response_type_id_token,
            login_hint,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_authorization_grant.lookup",
        skip_all,
        fields(
            db.query.text,
            grant.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<AuthorizationGrant>, Self::Error> {
        let res = sqlx::query_as!(
            GrantLookup,
            r#"
                SELECT oauth2_authorization_grant_id
                     , created_at
                     , cancelled_at
                     , fulfilled_at
                     , exchanged_at
                     , scope
                     , state
                     , redirect_uri
                     , response_mode
                     , nonce
                     , oauth2_client_id
                     , authorization_code
                     , response_type_code
                     , response_type_id_token
                     , code_challenge
                     , code_challenge_method
                     , login_hint
                     , oauth2_session_id
                FROM
                    oauth2_authorization_grants

                WHERE oauth2_authorization_grant_id = $1
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
        name = "db.oauth2_authorization_grant.find_by_code",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn find_by_code(
        &mut self,
        code: &str,
    ) -> Result<Option<AuthorizationGrant>, Self::Error> {
        let res = sqlx::query_as!(
            GrantLookup,
            r#"
                SELECT oauth2_authorization_grant_id
                     , created_at
                     , cancelled_at
                     , fulfilled_at
                     , exchanged_at
                     , scope
                     , state
                     , redirect_uri
                     , response_mode
                     , nonce
                     , oauth2_client_id
                     , authorization_code
                     , response_type_code
                     , response_type_id_token
                     , code_challenge
                     , code_challenge_method
                     , login_hint
                     , oauth2_session_id
                FROM
                    oauth2_authorization_grants

                WHERE authorization_code = $1
            "#,
            code,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_authorization_grant.fulfill",
        skip_all,
        fields(
            db.query.text,
            %grant.id,
            client.id = %grant.client_id,
            %session.id,
        ),
        err,
    )]
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        session: &Session,
        grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error> {
        let fulfilled_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_authorization_grants
                SET fulfilled_at = $2
                  , oauth2_session_id = $3
                WHERE oauth2_authorization_grant_id = $1
            "#,
            Uuid::from(grant.id),
            fulfilled_at,
            Uuid::from(session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        // XXX: check affected rows & new methods
        let grant = grant
            .fulfill(fulfilled_at, session)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(grant)
    }

    #[tracing::instrument(
        name = "db.oauth2_authorization_grant.exchange",
        skip_all,
        fields(
            db.query.text,
            %grant.id,
            client.id = %grant.client_id,
        ),
        err,
    )]
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error> {
        let exchanged_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE oauth2_authorization_grants
                SET exchanged_at = $2
                WHERE oauth2_authorization_grant_id = $1
            "#,
            Uuid::from(grant.id),
            exchanged_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        let grant = grant
            .exchange(exchanged_at)
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(grant)
    }
}
