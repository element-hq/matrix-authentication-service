// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    collections::{BTreeMap, BTreeSet},
    string::ToString,
};

use async_trait::async_trait;
use mas_data_model::{Client, Clock, JwksOrJwksUri};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_jose::jwk::PublicJsonWebKeySet;
use mas_storage::oauth2::OAuth2ClientRepository;
use oauth2_types::{oidc::ApplicationType, requests::GrantType};
use opentelemetry_semantic_conventions::attribute::DB_QUERY_TEXT;
use rand::RngCore;
use sqlx::PgConnection;
use tracing::{Instrument, info_span};
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseInconsistencyError, tracing::ExecuteExt};

/// An implementation of [`OAuth2ClientRepository`] for a PostgreSQL connection
pub struct PgOAuth2ClientRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgOAuth2ClientRepository<'c> {
    /// Create a new [`PgOAuth2ClientRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
struct OAuth2ClientLookup {
    oauth2_client_id: Uuid,
    metadata_digest: Option<String>,
    encrypted_client_secret: Option<String>,
    application_type: Option<String>,
    redirect_uris: Vec<String>,
    grant_type_authorization_code: bool,
    grant_type_refresh_token: bool,
    grant_type_client_credentials: bool,
    grant_type_device_code: bool,
    client_name: Option<String>,
    logo_uri: Option<String>,
    client_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<serde_json::Value>,
    id_token_signed_response_alg: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    token_endpoint_auth_method: Option<String>,
    token_endpoint_auth_signing_alg: Option<String>,
    initiate_login_uri: Option<String>,
}

impl TryInto<Client> for OAuth2ClientLookup {
    type Error = DatabaseInconsistencyError;

    fn try_into(self) -> Result<Client, Self::Error> {
        let id = Ulid::from(self.oauth2_client_id);

        let redirect_uris: Result<Vec<Url>, _> =
            self.redirect_uris.iter().map(|s| s.parse()).collect();
        let redirect_uris = redirect_uris.map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("redirect_uris")
                .row(id)
                .source(e)
        })?;

        let application_type = self
            .application_type
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("application_type")
                    .row(id)
                    .source(e)
            })?;

        let mut grant_types = Vec::new();
        if self.grant_type_authorization_code {
            grant_types.push(GrantType::AuthorizationCode);
        }
        if self.grant_type_refresh_token {
            grant_types.push(GrantType::RefreshToken);
        }
        if self.grant_type_client_credentials {
            grant_types.push(GrantType::ClientCredentials);
        }
        if self.grant_type_device_code {
            grant_types.push(GrantType::DeviceCode);
        }

        let logo_uri = self.logo_uri.map(|s| s.parse()).transpose().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("logo_uri")
                .row(id)
                .source(e)
        })?;

        let client_uri = self
            .client_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("client_uri")
                    .row(id)
                    .source(e)
            })?;

        let policy_uri = self
            .policy_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("policy_uri")
                    .row(id)
                    .source(e)
            })?;

        let tos_uri = self.tos_uri.map(|s| s.parse()).transpose().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("tos_uri")
                .row(id)
                .source(e)
        })?;

        let id_token_signed_response_alg = self
            .id_token_signed_response_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("id_token_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let userinfo_signed_response_alg = self
            .userinfo_signed_response_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("userinfo_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_auth_method = self
            .token_endpoint_auth_method
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("token_endpoint_auth_method")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_auth_signing_alg = self
            .token_endpoint_auth_signing_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("token_endpoint_auth_signing_alg")
                    .row(id)
                    .source(e)
            })?;

        let initiate_login_uri = self
            .initiate_login_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("initiate_login_uri")
                    .row(id)
                    .source(e)
            })?;

        let jwks = match (self.jwks, self.jwks_uri) {
            (None, None) => None,
            (Some(jwks), None) => {
                let jwks = serde_json::from_value(jwks).map_err(|e| {
                    DatabaseInconsistencyError::on("oauth2_clients")
                        .column("jwks")
                        .row(id)
                        .source(e)
                })?;
                Some(JwksOrJwksUri::Jwks(jwks))
            }
            (None, Some(jwks_uri)) => {
                let jwks_uri = jwks_uri.parse().map_err(|e| {
                    DatabaseInconsistencyError::on("oauth2_clients")
                        .column("jwks_uri")
                        .row(id)
                        .source(e)
                })?;

                Some(JwksOrJwksUri::JwksUri(jwks_uri))
            }
            _ => {
                return Err(DatabaseInconsistencyError::on("oauth2_clients")
                    .column("jwks(_uri)")
                    .row(id));
            }
        };

        Ok(Client {
            id,
            client_id: id.to_string(),
            metadata_digest: self.metadata_digest,
            encrypted_client_secret: self.encrypted_client_secret,
            application_type,
            redirect_uris,
            grant_types,
            client_name: self.client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
            jwks,
            id_token_signed_response_alg,
            userinfo_signed_response_alg,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            initiate_login_uri,
        })
    }
}

#[async_trait]
impl OAuth2ClientRepository for PgOAuth2ClientRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.oauth2_client.lookup",
        skip_all,
        fields(
            db.query.text,
            oauth2_client.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Client>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2ClientLookup,
            r#"
                SELECT oauth2_client_id
                     , metadata_digest
                     , encrypted_client_secret
                     , application_type
                     , redirect_uris
                     , grant_type_authorization_code
                     , grant_type_refresh_token
                     , grant_type_client_credentials
                     , grant_type_device_code
                     , client_name
                     , logo_uri
                     , client_uri
                     , policy_uri
                     , tos_uri
                     , jwks_uri
                     , jwks
                     , id_token_signed_response_alg
                     , userinfo_signed_response_alg
                     , token_endpoint_auth_method
                     , token_endpoint_auth_signing_alg
                     , initiate_login_uri
                FROM oauth2_clients c

                WHERE oauth2_client_id = $1
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
        name = "db.oauth2_client.find_by_metadata_digest",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn find_by_metadata_digest(
        &mut self,
        digest: &str,
    ) -> Result<Option<Client>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2ClientLookup,
            r#"
                SELECT oauth2_client_id
                    , metadata_digest
                    , encrypted_client_secret
                    , application_type
                    , redirect_uris
                    , grant_type_authorization_code
                    , grant_type_refresh_token
                    , grant_type_client_credentials
                    , grant_type_device_code
                    , client_name
                    , logo_uri
                    , client_uri
                    , policy_uri
                    , tos_uri
                    , jwks_uri
                    , jwks
                    , id_token_signed_response_alg
                    , userinfo_signed_response_alg
                    , token_endpoint_auth_method
                    , token_endpoint_auth_signing_alg
                    , initiate_login_uri
                FROM oauth2_clients
                WHERE metadata_digest = $1
            "#,
            digest,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else { return Ok(None) };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.oauth2_client.load_batch",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn load_batch(
        &mut self,
        ids: BTreeSet<Ulid>,
    ) -> Result<BTreeMap<Ulid, Client>, Self::Error> {
        let ids: Vec<Uuid> = ids.into_iter().map(Uuid::from).collect();
        let res = sqlx::query_as!(
            OAuth2ClientLookup,
            r#"
                SELECT oauth2_client_id
                     , metadata_digest
                     , encrypted_client_secret
                     , application_type
                     , redirect_uris
                     , grant_type_authorization_code
                     , grant_type_refresh_token
                     , grant_type_client_credentials
                     , grant_type_device_code
                     , client_name
                     , logo_uri
                     , client_uri
                     , policy_uri
                     , tos_uri
                     , jwks_uri
                     , jwks
                     , id_token_signed_response_alg
                     , userinfo_signed_response_alg
                     , token_endpoint_auth_method
                     , token_endpoint_auth_signing_alg
                     , initiate_login_uri
                FROM oauth2_clients c

                WHERE oauth2_client_id = ANY($1::uuid[])
            "#,
            &ids,
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        res.into_iter()
            .map(|r| {
                r.try_into()
                    .map(|c: Client| (c.id, c))
                    .map_err(DatabaseError::from)
            })
            .collect()
    }

    #[tracing::instrument(
        name = "db.oauth2_client.add",
        skip_all,
        fields(
            db.query.text,
            client.id,
            client.name = client_name
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        redirect_uris: Vec<Url>,
        metadata_digest: Option<String>,
        encrypted_client_secret: Option<String>,
        application_type: Option<ApplicationType>,
        grant_types: Vec<GrantType>,
        client_name: Option<String>,
        logo_uri: Option<Url>,
        client_uri: Option<Url>,
        policy_uri: Option<Url>,
        tos_uri: Option<Url>,
        jwks_uri: Option<Url>,
        jwks: Option<PublicJsonWebKeySet>,
        id_token_signed_response_alg: Option<JsonWebSignatureAlg>,
        userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
        token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,
        token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
        initiate_login_uri: Option<Url>,
    ) -> Result<Client, Self::Error> {
        let now = clock.now();
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        tracing::Span::current().record("client.id", tracing::field::display(id));

        let jwks_json = jwks
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        let redirect_uris_array = redirect_uris.iter().map(Url::to_string).collect::<Vec<_>>();

        sqlx::query!(
            r#"
                INSERT INTO oauth2_clients
                    ( oauth2_client_id
                    , metadata_digest
                    , encrypted_client_secret
                    , application_type
                    , redirect_uris
                    , grant_type_authorization_code
                    , grant_type_refresh_token
                    , grant_type_client_credentials
                    , grant_type_device_code
                    , client_name
                    , logo_uri
                    , client_uri
                    , policy_uri
                    , tos_uri
                    , jwks_uri
                    , jwks
                    , id_token_signed_response_alg
                    , userinfo_signed_response_alg
                    , token_endpoint_auth_method
                    , token_endpoint_auth_signing_alg
                    , initiate_login_uri
                    , is_static
                    )
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                    $14, $15, $16, $17, $18, $19, $20, $21, FALSE)
            "#,
            Uuid::from(id),
            metadata_digest,
            encrypted_client_secret,
            application_type.as_ref().map(ToString::to_string),
            &redirect_uris_array,
            grant_types.contains(&GrantType::AuthorizationCode),
            grant_types.contains(&GrantType::RefreshToken),
            grant_types.contains(&GrantType::ClientCredentials),
            grant_types.contains(&GrantType::DeviceCode),
            client_name,
            logo_uri.as_ref().map(Url::as_str),
            client_uri.as_ref().map(Url::as_str),
            policy_uri.as_ref().map(Url::as_str),
            tos_uri.as_ref().map(Url::as_str),
            jwks_uri.as_ref().map(Url::as_str),
            jwks_json,
            id_token_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            userinfo_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            token_endpoint_auth_method.as_ref().map(ToString::to_string),
            token_endpoint_auth_signing_alg
                .as_ref()
                .map(ToString::to_string),
            initiate_login_uri.as_ref().map(Url::as_str),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let jwks = match (jwks, jwks_uri) {
            (None, None) => None,
            (Some(jwks), None) => Some(JwksOrJwksUri::Jwks(jwks)),
            (None, Some(jwks_uri)) => Some(JwksOrJwksUri::JwksUri(jwks_uri)),
            _ => return Err(DatabaseError::invalid_operation()),
        };

        Ok(Client {
            id,
            client_id: id.to_string(),
            metadata_digest: None,
            encrypted_client_secret,
            application_type,
            redirect_uris,
            grant_types,
            client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
            jwks,
            id_token_signed_response_alg,
            userinfo_signed_response_alg,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            initiate_login_uri,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_client.upsert_static",
        skip_all,
        fields(
            db.query.text,
            client.id = %client_id,
        ),
        err,
    )]
    async fn upsert_static(
        &mut self,
        client_id: Ulid,
        client_name: Option<String>,
        client_auth_method: OAuthClientAuthenticationMethod,
        encrypted_client_secret: Option<String>,
        jwks: Option<PublicJsonWebKeySet>,
        jwks_uri: Option<Url>,
        redirect_uris: Vec<Url>,
    ) -> Result<Client, Self::Error> {
        let jwks_json = jwks
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        let client_auth_method = client_auth_method.to_string();
        let redirect_uris_array = redirect_uris.iter().map(Url::to_string).collect::<Vec<_>>();

        sqlx::query!(
            r#"
                INSERT INTO oauth2_clients
                    ( oauth2_client_id
                    , encrypted_client_secret
                    , redirect_uris
                    , grant_type_authorization_code
                    , grant_type_refresh_token
                    , grant_type_client_credentials
                    , grant_type_device_code
                    , token_endpoint_auth_method
                    , jwks
                    , client_name
                    , jwks_uri
                    , is_static
                    )
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE)
                ON CONFLICT (oauth2_client_id)
                DO
                    UPDATE SET encrypted_client_secret = EXCLUDED.encrypted_client_secret
                             , redirect_uris = EXCLUDED.redirect_uris
                             , grant_type_authorization_code = EXCLUDED.grant_type_authorization_code
                             , grant_type_refresh_token = EXCLUDED.grant_type_refresh_token
                             , grant_type_client_credentials = EXCLUDED.grant_type_client_credentials
                             , grant_type_device_code = EXCLUDED.grant_type_device_code
                             , token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method
                             , jwks = EXCLUDED.jwks
                             , client_name = EXCLUDED.client_name
                             , jwks_uri = EXCLUDED.jwks_uri
                             , is_static = TRUE
            "#,
            Uuid::from(client_id),
            encrypted_client_secret,
            &redirect_uris_array,
            true,
            true,
            true,
            true,
            client_auth_method,
            jwks_json,
            client_name,
            jwks_uri.as_ref().map(Url::as_str),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let jwks = match (jwks, jwks_uri) {
            (None, None) => None,
            (Some(jwks), None) => Some(JwksOrJwksUri::Jwks(jwks)),
            (None, Some(jwks_uri)) => Some(JwksOrJwksUri::JwksUri(jwks_uri)),
            _ => return Err(DatabaseError::invalid_operation()),
        };

        Ok(Client {
            id: client_id,
            client_id: client_id.to_string(),
            metadata_digest: None,
            encrypted_client_secret,
            application_type: None,
            redirect_uris,
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
                GrantType::ClientCredentials,
            ],
            client_name,
            logo_uri: None,
            client_uri: None,
            policy_uri: None,
            tos_uri: None,
            jwks,
            id_token_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            token_endpoint_auth_method: None,
            token_endpoint_auth_signing_alg: None,
            initiate_login_uri: None,
        })
    }

    #[tracing::instrument(
        name = "db.oauth2_client.all_static",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn all_static(&mut self) -> Result<Vec<Client>, Self::Error> {
        let res = sqlx::query_as!(
            OAuth2ClientLookup,
            r#"
                SELECT oauth2_client_id
                     , metadata_digest
                     , encrypted_client_secret
                     , application_type
                     , redirect_uris
                     , grant_type_authorization_code
                     , grant_type_refresh_token
                     , grant_type_client_credentials
                     , grant_type_device_code
                     , client_name
                     , logo_uri
                     , client_uri
                     , policy_uri
                     , tos_uri
                     , jwks_uri
                     , jwks
                     , id_token_signed_response_alg
                     , userinfo_signed_response_alg
                     , token_endpoint_auth_method
                     , token_endpoint_auth_signing_alg
                     , initiate_login_uri
                FROM oauth2_clients c
                WHERE is_static = TRUE
            "#,
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        res.into_iter()
            .map(|r| r.try_into().map_err(DatabaseError::from))
            .collect()
    }

    #[tracing::instrument(
        name = "db.oauth2_client.delete_by_id",
        skip_all,
        fields(
            db.query.text,
            client.id = %id,
        ),
        err,
    )]
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error> {
        // Delete the authorization grants
        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.authorization_grants",
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM oauth2_authorization_grants
                    WHERE oauth2_client_id = $1
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        // Delete the OAuth 2 sessions related data
        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.access_tokens",
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM oauth2_access_tokens
                    WHERE oauth2_session_id IN (
                        SELECT oauth2_session_id
                        FROM oauth2_sessions
                        WHERE oauth2_client_id = $1
                    )
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.refresh_tokens",
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM oauth2_refresh_tokens
                    WHERE oauth2_session_id IN (
                        SELECT oauth2_session_id
                        FROM oauth2_sessions
                        WHERE oauth2_client_id = $1
                    )
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.sessions",
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM oauth2_sessions
                    WHERE oauth2_client_id = $1
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        // Delete any personal access tokens & sessions owned
        // by the client
        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.personal_access_tokens",
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM personal_access_tokens
                    WHERE personal_session_id IN (
                        SELECT personal_session_id
                        FROM personal_sessions
                        WHERE owner_oauth2_client_id = $1
                    )
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }
        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.personal_sessions",
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );

            sqlx::query!(
                r#"
                    DELETE FROM personal_sessions
                    WHERE owner_oauth2_client_id = $1
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        // Now delete the client itself
        let res = sqlx::query!(
            r#"
                DELETE FROM oauth2_clients
                WHERE oauth2_client_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)
    }
}
