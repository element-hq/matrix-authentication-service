// Copyright 2025, 2026 Element Creations Ltd.
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
use mas_data_model::{Client, Clock, JwksOrJwksUri, UlidExt as _};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_jose::jwk::PublicJsonWebKeySet;
use mas_storage::{
    Page, Pagination,
    oauth2::{OAuth2ClientFilter, OAuth2ClientKind, OAuth2ClientRepository},
    pagination::Node,
};
use oauth2_types::{oidc::ApplicationType, requests::GrantType};
use opentelemetry_semantic_conventions::attribute::DB_QUERY_TEXT;
use rand::RngCore;
use sea_query::{
    Expr, ExprTrait, PostgresQueryBuilder, Query, SimpleExpr, enum_def,
    extension::postgres::PgExpr as _,
};
use sea_query_sqlx::SqlxBinder;
use sqlx::PgConnection;
use tracing::{Instrument, info_span};
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    filter::{Filter, StatementExt},
    iden::{OAuth2Clients, OAuth2Sessions},
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

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

#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, sqlx::FromRow)]
#[enum_def]
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
    is_static: bool,
    skip_consent: bool,
}

impl Node<Ulid> for OAuth2ClientLookup {
    fn cursor(&self) -> Ulid {
        self.oauth2_client_id.into()
    }
}

impl Filter for OAuth2ClientFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.kind().map(|kind| {
                let is_static = matches!(kind, OAuth2ClientKind::Static);
                Expr::col((OAuth2Clients::Table, OAuth2Clients::IsStatic)).eq(is_static)
            }))
            .add_option(self.client_name().map(|client_name| {
                Expr::col((OAuth2Clients::Table, OAuth2Clients::ClientName))
                    .ilike(format!("%{client_name}%"))
            }))
            .add_option(self.client_uri().map(|client_uri| {
                Expr::col((OAuth2Clients::Table, OAuth2Clients::ClientUri))
                    .ilike(format!("%{client_uri}%"))
            }))
            .add_option(self.grant_type().map(|grant_type| -> SimpleExpr {
                let column = match grant_type {
                    GrantType::AuthorizationCode => OAuth2Clients::GrantTypeAuthorizationCode,
                    GrantType::RefreshToken => OAuth2Clients::GrantTypeRefreshToken,
                    GrantType::ClientCredentials => OAuth2Clients::GrantTypeClientCredentials,
                    GrantType::DeviceCode => OAuth2Clients::GrantTypeDeviceCode,
                    // The other grant types don't have a dedicated column, so no
                    // client can declare them: the filter matches nothing.
                    _ => return Expr::val(false),
                };
                Expr::col((OAuth2Clients::Table, column)).eq(true)
            }))
            .add_option(self.has_active_sessions().map(|has| -> SimpleExpr {
                let exists = Expr::exists(
                    Query::select()
                        .expr(Expr::cust("1"))
                        .from(OAuth2Sessions::Table)
                        .and_where(
                            Expr::col((OAuth2Sessions::Table, OAuth2Sessions::OAuth2ClientId))
                                .equals((OAuth2Clients::Table, OAuth2Clients::OAuth2ClientId)),
                        )
                        .and_where(
                            Expr::col((OAuth2Sessions::Table, OAuth2Sessions::FinishedAt))
                                .is_null(),
                        )
                        .take(),
                );
                if has { exists } else { exists.not() }
            }))
    }
}

impl TryFrom<OAuth2ClientLookup> for Client {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: OAuth2ClientLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.oauth2_client_id);

        let redirect_uris: Result<Vec<Url>, _> =
            value.redirect_uris.iter().map(|s| s.parse()).collect();
        let redirect_uris = redirect_uris.map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("redirect_uris")
                .row(id)
                .source(e)
        })?;

        let application_type = value
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
        if value.grant_type_authorization_code {
            grant_types.push(GrantType::AuthorizationCode);
        }
        if value.grant_type_refresh_token {
            grant_types.push(GrantType::RefreshToken);
        }
        if value.grant_type_client_credentials {
            grant_types.push(GrantType::ClientCredentials);
        }
        if value.grant_type_device_code {
            grant_types.push(GrantType::DeviceCode);
        }

        let logo_uri = value.logo_uri.map(|s| s.parse()).transpose().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("logo_uri")
                .row(id)
                .source(e)
        })?;

        let client_uri = value
            .client_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("client_uri")
                    .row(id)
                    .source(e)
            })?;

        let policy_uri = value
            .policy_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("policy_uri")
                    .row(id)
                    .source(e)
            })?;

        let tos_uri = value.tos_uri.map(|s| s.parse()).transpose().map_err(|e| {
            DatabaseInconsistencyError::on("oauth2_clients")
                .column("tos_uri")
                .row(id)
                .source(e)
        })?;

        let id_token_signed_response_alg = value
            .id_token_signed_response_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("id_token_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let userinfo_signed_response_alg = value
            .userinfo_signed_response_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("userinfo_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_auth_method = value
            .token_endpoint_auth_method
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("token_endpoint_auth_method")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_auth_signing_alg = value
            .token_endpoint_auth_signing_alg
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("token_endpoint_auth_signing_alg")
                    .row(id)
                    .source(e)
            })?;

        let initiate_login_uri = value
            .initiate_login_uri
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("oauth2_clients")
                    .column("initiate_login_uri")
                    .row(id)
                    .source(e)
            })?;

        let jwks = match (value.jwks, value.jwks_uri) {
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
            metadata_digest: value.metadata_digest,
            encrypted_client_secret: value.encrypted_client_secret,
            application_type,
            redirect_uris,
            grant_types,
            client_name: value.client_name,
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
            is_static: value.is_static,
            skip_consent: value.skip_consent,
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
                     , is_static
                     , skip_consent
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
                    , is_static
                    , skip_consent
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
                     , is_static
                     , skip_consent
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
        let id = Ulid::from_datetime_with_rng(now, rng);
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
            is_static: false,
            skip_consent: false,
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
        skip_consent: bool,
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
                    , skip_consent
                    )
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE, $12)
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
                             , skip_consent = EXCLUDED.skip_consent
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
            skip_consent,
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
            is_static: true,
            skip_consent,
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
                     , is_static
                     , skip_consent
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

    #[tracing::instrument(
        name = "db.oauth2_client.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: OAuth2ClientFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<Client>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((OAuth2Clients::Table, OAuth2Clients::OAuth2ClientId)),
                OAuth2ClientLookupIden::Oauth2ClientId,
            )
            .expr_as(
                Expr::cust("metadata_digest"),
                OAuth2ClientLookupIden::MetadataDigest,
            )
            .expr_as(
                Expr::cust("encrypted_client_secret"),
                OAuth2ClientLookupIden::EncryptedClientSecret,
            )
            .expr_as(
                Expr::cust("application_type"),
                OAuth2ClientLookupIden::ApplicationType,
            )
            .expr_as(
                Expr::col((OAuth2Clients::Table, OAuth2Clients::RedirectUris)),
                OAuth2ClientLookupIden::RedirectUris,
            )
            .expr_as(
                Expr::cust("grant_type_authorization_code"),
                OAuth2ClientLookupIden::GrantTypeAuthorizationCode,
            )
            .expr_as(
                Expr::cust("grant_type_refresh_token"),
                OAuth2ClientLookupIden::GrantTypeRefreshToken,
            )
            .expr_as(
                Expr::cust("grant_type_client_credentials"),
                OAuth2ClientLookupIden::GrantTypeClientCredentials,
            )
            .expr_as(
                Expr::cust("grant_type_device_code"),
                OAuth2ClientLookupIden::GrantTypeDeviceCode,
            )
            .expr_as(
                Expr::col((OAuth2Clients::Table, OAuth2Clients::ClientName)),
                OAuth2ClientLookupIden::ClientName,
            )
            .expr_as(
                Expr::col((OAuth2Clients::Table, OAuth2Clients::LogoUri)),
                OAuth2ClientLookupIden::LogoUri,
            )
            .expr_as(
                Expr::col((OAuth2Clients::Table, OAuth2Clients::ClientUri)),
                OAuth2ClientLookupIden::ClientUri,
            )
            .expr_as(Expr::cust("policy_uri"), OAuth2ClientLookupIden::PolicyUri)
            .expr_as(Expr::cust("tos_uri"), OAuth2ClientLookupIden::TosUri)
            .expr_as(Expr::cust("jwks_uri"), OAuth2ClientLookupIden::JwksUri)
            .expr_as(Expr::cust("jwks"), OAuth2ClientLookupIden::Jwks)
            .expr_as(
                Expr::cust("id_token_signed_response_alg"),
                OAuth2ClientLookupIden::IdTokenSignedResponseAlg,
            )
            .expr_as(
                Expr::cust("userinfo_signed_response_alg"),
                OAuth2ClientLookupIden::UserinfoSignedResponseAlg,
            )
            .expr_as(
                Expr::cust("token_endpoint_auth_method"),
                OAuth2ClientLookupIden::TokenEndpointAuthMethod,
            )
            .expr_as(
                Expr::cust("token_endpoint_auth_signing_alg"),
                OAuth2ClientLookupIden::TokenEndpointAuthSigningAlg,
            )
            .expr_as(
                Expr::cust("initiate_login_uri"),
                OAuth2ClientLookupIden::InitiateLoginUri,
            )
            .expr_as(
                Expr::cust("skip_consent"),
                OAuth2ClientLookupIden::SkipConsent,
            )
            .expr_as(
                Expr::col((OAuth2Clients::Table, OAuth2Clients::IsStatic)),
                OAuth2ClientLookupIden::IsStatic,
            )
            .from(OAuth2Clients::Table)
            .apply_filter(filter)
            .generate_pagination(
                (OAuth2Clients::Table, OAuth2Clients::OAuth2ClientId),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<OAuth2ClientLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination.process(edges).try_map(Client::try_from)?;

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.oauth2_client.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn count(&mut self, filter: OAuth2ClientFilter<'_>) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(Expr::col((OAuth2Clients::Table, OAuth2Clients::OAuth2ClientId)).count())
            .from(OAuth2Clients::Table)
            .apply_filter(filter)
            .build_sqlx(PostgresQueryBuilder);

        let count: i64 = sqlx::query_scalar_with(&sql, arguments)
            .traced()
            .fetch_one(&mut *self.conn)
            .await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }
}
