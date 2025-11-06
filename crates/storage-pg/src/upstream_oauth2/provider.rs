// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{Clock, UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports};
use mas_storage::{
    Page, Pagination,
    pagination::Node,
    upstream_oauth2::{
        UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
    },
};
use opentelemetry_semantic_conventions::attribute::DB_QUERY_TEXT;
use rand::RngCore;
use sea_query::{Expr, PostgresQueryBuilder, Query, enum_def};
use sea_query_binder::SqlxBinder;
use sqlx::{PgConnection, types::Json};
use tracing::{Instrument, info_span};
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseError, DatabaseInconsistencyError,
    filter::{Filter, StatementExt},
    iden::UpstreamOAuthProviders,
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

/// An implementation of [`UpstreamOAuthProviderRepository`] for a PostgreSQL
/// connection
pub struct PgUpstreamOAuthProviderRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUpstreamOAuthProviderRepository<'c> {
    /// Create a new [`PgUpstreamOAuthProviderRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(sqlx::FromRow)]
#[enum_def]
struct ProviderLookup {
    upstream_oauth_provider_id: Uuid,
    issuer: Option<String>,
    human_name: Option<String>,
    brand_name: Option<String>,
    scope: String,
    client_id: String,
    encrypted_client_secret: Option<String>,
    token_endpoint_signing_alg: Option<String>,
    token_endpoint_auth_method: String,
    id_token_signed_response_alg: String,
    fetch_userinfo: bool,
    userinfo_signed_response_alg: Option<String>,
    created_at: DateTime<Utc>,
    disabled_at: Option<DateTime<Utc>>,
    claims_imports: Json<UpstreamOAuthProviderClaimsImports>,
    jwks_uri_override: Option<String>,
    authorization_endpoint_override: Option<String>,
    token_endpoint_override: Option<String>,
    userinfo_endpoint_override: Option<String>,
    discovery_mode: String,
    pkce_mode: String,
    response_mode: Option<String>,
    additional_parameters: Option<Json<Vec<(String, String)>>>,
    forward_login_hint: bool,
    on_backchannel_logout: String,
}

impl Node<Ulid> for ProviderLookup {
    fn cursor(&self) -> Ulid {
        self.upstream_oauth_provider_id.into()
    }
}

impl TryFrom<ProviderLookup> for UpstreamOAuthProvider {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: ProviderLookup) -> Result<Self, Self::Error> {
        let id = value.upstream_oauth_provider_id.into();
        let scope = value.scope.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("scope")
                .row(id)
                .source(e)
        })?;
        let token_endpoint_auth_method = value.token_endpoint_auth_method.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("token_endpoint_auth_method")
                .row(id)
                .source(e)
        })?;
        let token_endpoint_signing_alg = value
            .token_endpoint_signing_alg
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("token_endpoint_signing_alg")
                    .row(id)
                    .source(e)
            })?;
        let id_token_signed_response_alg =
            value.id_token_signed_response_alg.parse().map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("id_token_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let userinfo_signed_response_alg = value
            .userinfo_signed_response_alg
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("userinfo_signed_response_alg")
                    .row(id)
                    .source(e)
            })?;

        let authorization_endpoint_override = value
            .authorization_endpoint_override
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("authorization_endpoint_override")
                    .row(id)
                    .source(e)
            })?;

        let token_endpoint_override = value
            .token_endpoint_override
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("token_endpoint_override")
                    .row(id)
                    .source(e)
            })?;

        let userinfo_endpoint_override = value
            .userinfo_endpoint_override
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("userinfo_endpoint_override")
                    .row(id)
                    .source(e)
            })?;

        let jwks_uri_override = value
            .jwks_uri_override
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("jwks_uri_override")
                    .row(id)
                    .source(e)
            })?;

        let discovery_mode = value.discovery_mode.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("discovery_mode")
                .row(id)
                .source(e)
        })?;

        let pkce_mode = value.pkce_mode.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("pkce_mode")
                .row(id)
                .source(e)
        })?;

        let response_mode = value
            .response_mode
            .map(|x| x.parse())
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("upstream_oauth_providers")
                    .column("response_mode")
                    .row(id)
                    .source(e)
            })?;

        let additional_authorization_parameters = value
            .additional_parameters
            .map(|Json(x)| x)
            .unwrap_or_default();

        let on_backchannel_logout = value.on_backchannel_logout.parse().map_err(|e| {
            DatabaseInconsistencyError::on("upstream_oauth_providers")
                .column("on_backchannel_logout")
                .row(id)
                .source(e)
        })?;

        Ok(UpstreamOAuthProvider {
            id,
            issuer: value.issuer,
            human_name: value.human_name,
            brand_name: value.brand_name,
            scope,
            client_id: value.client_id,
            encrypted_client_secret: value.encrypted_client_secret,
            token_endpoint_auth_method,
            token_endpoint_signing_alg,
            id_token_signed_response_alg,
            fetch_userinfo: value.fetch_userinfo,
            userinfo_signed_response_alg,
            created_at: value.created_at,
            disabled_at: value.disabled_at,
            claims_imports: value.claims_imports.0,
            authorization_endpoint_override,
            token_endpoint_override,
            userinfo_endpoint_override,
            jwks_uri_override,
            discovery_mode,
            pkce_mode,
            response_mode,
            additional_authorization_parameters,
            forward_login_hint: value.forward_login_hint,
            on_backchannel_logout,
        })
    }
}

impl Filter for UpstreamOAuthProviderFilter<'_> {
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all().add_option(self.enabled().map(|enabled| {
            Expr::col((
                UpstreamOAuthProviders::Table,
                UpstreamOAuthProviders::DisabledAt,
            ))
            .is_null()
            .eq(enabled)
        }))
    }
}

#[async_trait]
impl UpstreamOAuthProviderRepository for PgUpstreamOAuthProviderRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.lookup",
        skip_all,
        fields(
            db.query.text,
            upstream_oauth_provider.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthProvider>, Self::Error> {
        let res = sqlx::query_as!(
            ProviderLookup,
            r#"
                SELECT
                    upstream_oauth_provider_id,
                    issuer,
                    human_name,
                    brand_name,
                    scope,
                    client_id,
                    encrypted_client_secret,
                    token_endpoint_signing_alg,
                    token_endpoint_auth_method,
                    id_token_signed_response_alg,
                    fetch_userinfo,
                    userinfo_signed_response_alg,
                    created_at,
                    disabled_at,
                    claims_imports as "claims_imports: Json<UpstreamOAuthProviderClaimsImports>",
                    jwks_uri_override,
                    authorization_endpoint_override,
                    token_endpoint_override,
                    userinfo_endpoint_override,
                    discovery_mode,
                    pkce_mode,
                    response_mode,
                    additional_parameters as "additional_parameters: Json<Vec<(String, String)>>",
                    forward_login_hint,
                    on_backchannel_logout
                FROM upstream_oauth_providers
                WHERE upstream_oauth_provider_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let res = res
            .map(UpstreamOAuthProvider::try_from)
            .transpose()
            .map_err(DatabaseError::from)?;

        Ok(res)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.add",
        skip_all,
        fields(
            db.query.text,
            upstream_oauth_provider.id,
            upstream_oauth_provider.issuer = params.issuer,
            upstream_oauth_provider.client_id = %params.client_id,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: UpstreamOAuthProviderParams,
    ) -> Result<UpstreamOAuthProvider, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("upstream_oauth_provider.id", tracing::field::display(id));

        sqlx::query!(
            r#"
            INSERT INTO upstream_oauth_providers (
                upstream_oauth_provider_id,
                issuer,
                human_name,
                brand_name,
                scope,
                token_endpoint_auth_method,
                token_endpoint_signing_alg,
                id_token_signed_response_alg,
                fetch_userinfo,
                userinfo_signed_response_alg,
                client_id,
                encrypted_client_secret,
                claims_imports,
                authorization_endpoint_override,
                token_endpoint_override,
                userinfo_endpoint_override,
                jwks_uri_override,
                discovery_mode,
                pkce_mode,
                response_mode,
                forward_login_hint,
                on_backchannel_logout,
                created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                      $12, $13, $14, $15, $16, $17, $18, $19, $20,
                      $21, $22, $23)
        "#,
            Uuid::from(id),
            params.issuer.as_deref(),
            params.human_name.as_deref(),
            params.brand_name.as_deref(),
            params.scope.to_string(),
            params.token_endpoint_auth_method.to_string(),
            params
                .token_endpoint_signing_alg
                .as_ref()
                .map(ToString::to_string),
            params.id_token_signed_response_alg.to_string(),
            params.fetch_userinfo,
            params
                .userinfo_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            &params.client_id,
            params.encrypted_client_secret.as_deref(),
            Json(&params.claims_imports) as _,
            params
                .authorization_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            params
                .token_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            params
                .userinfo_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            params.jwks_uri_override.as_ref().map(ToString::to_string),
            params.discovery_mode.as_str(),
            params.pkce_mode.as_str(),
            params.response_mode.as_ref().map(ToString::to_string),
            params.forward_login_hint,
            params.on_backchannel_logout.as_str(),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UpstreamOAuthProvider {
            id,
            issuer: params.issuer,
            human_name: params.human_name,
            brand_name: params.brand_name,
            scope: params.scope,
            client_id: params.client_id,
            encrypted_client_secret: params.encrypted_client_secret,
            token_endpoint_signing_alg: params.token_endpoint_signing_alg,
            token_endpoint_auth_method: params.token_endpoint_auth_method,
            id_token_signed_response_alg: params.id_token_signed_response_alg,
            fetch_userinfo: params.fetch_userinfo,
            userinfo_signed_response_alg: params.userinfo_signed_response_alg,
            created_at,
            disabled_at: None,
            claims_imports: params.claims_imports,
            authorization_endpoint_override: params.authorization_endpoint_override,
            token_endpoint_override: params.token_endpoint_override,
            userinfo_endpoint_override: params.userinfo_endpoint_override,
            jwks_uri_override: params.jwks_uri_override,
            discovery_mode: params.discovery_mode,
            pkce_mode: params.pkce_mode,
            response_mode: params.response_mode,
            additional_authorization_parameters: params.additional_authorization_parameters,
            on_backchannel_logout: params.on_backchannel_logout,
            forward_login_hint: params.forward_login_hint,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.delete_by_id",
        skip_all,
        fields(
            db.query.text,
            upstream_oauth_provider.id = %id,
        ),
        err,
    )]
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error> {
        // Delete the authorization sessions first, as they have a foreign key
        // constraint on the links and the providers.
        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.authorization_sessions",
                upstream_oauth_provider.id = %id,
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );
            sqlx::query!(
                r#"
                    DELETE FROM upstream_oauth_authorization_sessions
                    WHERE upstream_oauth_provider_id = $1
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        // Delete the links next, as they have a foreign key constraint on the
        // providers.
        {
            let span = info_span!(
                "db.oauth2_client.delete_by_id.links",
                upstream_oauth_provider.id = %id,
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );
            sqlx::query!(
                r#"
                    DELETE FROM upstream_oauth_links
                    WHERE upstream_oauth_provider_id = $1
                "#,
                Uuid::from(id),
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;
        }

        let res = sqlx::query!(
            r#"
                DELETE FROM upstream_oauth_providers
                WHERE upstream_oauth_provider_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.add",
        skip_all,
        fields(
            db.query.text,
            upstream_oauth_provider.id = %id,
            upstream_oauth_provider.issuer = params.issuer,
            upstream_oauth_provider.client_id = %params.client_id,
        ),
        err,
    )]
    async fn upsert(
        &mut self,
        clock: &dyn Clock,
        id: Ulid,
        params: UpstreamOAuthProviderParams,
    ) -> Result<UpstreamOAuthProvider, Self::Error> {
        let created_at = clock.now();

        let created_at = sqlx::query_scalar!(
            r#"
                INSERT INTO upstream_oauth_providers (
                    upstream_oauth_provider_id,
                    issuer,
                    human_name,
                    brand_name,
                    scope,
                    token_endpoint_auth_method,
                    token_endpoint_signing_alg,
                    id_token_signed_response_alg,
                    fetch_userinfo,
                    userinfo_signed_response_alg,
                    client_id,
                    encrypted_client_secret,
                    claims_imports,
                    authorization_endpoint_override,
                    token_endpoint_override,
                    userinfo_endpoint_override,
                    jwks_uri_override,
                    discovery_mode,
                    pkce_mode,
                    response_mode,
                    additional_parameters,
                    forward_login_hint,
                    ui_order,
                    on_backchannel_logout,
                    created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                          $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                          $21, $22, $23, $24, $25)
                ON CONFLICT (upstream_oauth_provider_id)
                    DO UPDATE
                    SET
                        issuer = EXCLUDED.issuer,
                        human_name = EXCLUDED.human_name,
                        brand_name = EXCLUDED.brand_name,
                        scope = EXCLUDED.scope,
                        token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
                        token_endpoint_signing_alg = EXCLUDED.token_endpoint_signing_alg,
                        id_token_signed_response_alg = EXCLUDED.id_token_signed_response_alg,
                        fetch_userinfo = EXCLUDED.fetch_userinfo,
                        userinfo_signed_response_alg = EXCLUDED.userinfo_signed_response_alg,
                        disabled_at = NULL,
                        client_id = EXCLUDED.client_id,
                        encrypted_client_secret = EXCLUDED.encrypted_client_secret,
                        claims_imports = EXCLUDED.claims_imports,
                        authorization_endpoint_override = EXCLUDED.authorization_endpoint_override,
                        token_endpoint_override = EXCLUDED.token_endpoint_override,
                        userinfo_endpoint_override = EXCLUDED.userinfo_endpoint_override,
                        jwks_uri_override = EXCLUDED.jwks_uri_override,
                        discovery_mode = EXCLUDED.discovery_mode,
                        pkce_mode = EXCLUDED.pkce_mode,
                        response_mode = EXCLUDED.response_mode,
                        additional_parameters = EXCLUDED.additional_parameters,
                        forward_login_hint = EXCLUDED.forward_login_hint,
                        ui_order = EXCLUDED.ui_order,
                        on_backchannel_logout = EXCLUDED.on_backchannel_logout
                RETURNING created_at
            "#,
            Uuid::from(id),
            params.issuer.as_deref(),
            params.human_name.as_deref(),
            params.brand_name.as_deref(),
            params.scope.to_string(),
            params.token_endpoint_auth_method.to_string(),
            params
                .token_endpoint_signing_alg
                .as_ref()
                .map(ToString::to_string),
            params.id_token_signed_response_alg.to_string(),
            params.fetch_userinfo,
            params
                .userinfo_signed_response_alg
                .as_ref()
                .map(ToString::to_string),
            &params.client_id,
            params.encrypted_client_secret.as_deref(),
            Json(&params.claims_imports) as _,
            params
                .authorization_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            params
                .token_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            params
                .userinfo_endpoint_override
                .as_ref()
                .map(ToString::to_string),
            params.jwks_uri_override.as_ref().map(ToString::to_string),
            params.discovery_mode.as_str(),
            params.pkce_mode.as_str(),
            params.response_mode.as_ref().map(ToString::to_string),
            Json(&params.additional_authorization_parameters) as _,
            params.forward_login_hint,
            params.ui_order,
            params.on_backchannel_logout.as_str(),
            created_at,
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await?;

        Ok(UpstreamOAuthProvider {
            id,
            issuer: params.issuer,
            human_name: params.human_name,
            brand_name: params.brand_name,
            scope: params.scope,
            client_id: params.client_id,
            encrypted_client_secret: params.encrypted_client_secret,
            token_endpoint_signing_alg: params.token_endpoint_signing_alg,
            token_endpoint_auth_method: params.token_endpoint_auth_method,
            id_token_signed_response_alg: params.id_token_signed_response_alg,
            fetch_userinfo: params.fetch_userinfo,
            userinfo_signed_response_alg: params.userinfo_signed_response_alg,
            created_at,
            disabled_at: None,
            claims_imports: params.claims_imports,
            authorization_endpoint_override: params.authorization_endpoint_override,
            token_endpoint_override: params.token_endpoint_override,
            userinfo_endpoint_override: params.userinfo_endpoint_override,
            jwks_uri_override: params.jwks_uri_override,
            discovery_mode: params.discovery_mode,
            pkce_mode: params.pkce_mode,
            response_mode: params.response_mode,
            additional_authorization_parameters: params.additional_authorization_parameters,
            forward_login_hint: params.forward_login_hint,
            on_backchannel_logout: params.on_backchannel_logout,
        })
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.disable",
        skip_all,
        fields(
            db.query.text,
            %upstream_oauth_provider.id,
        ),
        err,
    )]
    async fn disable(
        &mut self,
        clock: &dyn Clock,
        mut upstream_oauth_provider: UpstreamOAuthProvider,
    ) -> Result<UpstreamOAuthProvider, Self::Error> {
        let disabled_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE upstream_oauth_providers
                SET disabled_at = $2
                WHERE upstream_oauth_provider_id = $1
            "#,
            Uuid::from(upstream_oauth_provider.id),
            disabled_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        upstream_oauth_provider.disabled_at = Some(disabled_at);

        Ok(upstream_oauth_provider)
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: UpstreamOAuthProviderFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthProvider>, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::UpstreamOAuthProviderId,
                )),
                ProviderLookupIden::UpstreamOauthProviderId,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::Issuer,
                )),
                ProviderLookupIden::Issuer,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::HumanName,
                )),
                ProviderLookupIden::HumanName,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::BrandName,
                )),
                ProviderLookupIden::BrandName,
            )
            .expr_as(
                Expr::col((UpstreamOAuthProviders::Table, UpstreamOAuthProviders::Scope)),
                ProviderLookupIden::Scope,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::ClientId,
                )),
                ProviderLookupIden::ClientId,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::EncryptedClientSecret,
                )),
                ProviderLookupIden::EncryptedClientSecret,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::TokenEndpointSigningAlg,
                )),
                ProviderLookupIden::TokenEndpointSigningAlg,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::TokenEndpointAuthMethod,
                )),
                ProviderLookupIden::TokenEndpointAuthMethod,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::IdTokenSignedResponseAlg,
                )),
                ProviderLookupIden::IdTokenSignedResponseAlg,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::FetchUserinfo,
                )),
                ProviderLookupIden::FetchUserinfo,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::UserinfoSignedResponseAlg,
                )),
                ProviderLookupIden::UserinfoSignedResponseAlg,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::CreatedAt,
                )),
                ProviderLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::DisabledAt,
                )),
                ProviderLookupIden::DisabledAt,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::ClaimsImports,
                )),
                ProviderLookupIden::ClaimsImports,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::JwksUriOverride,
                )),
                ProviderLookupIden::JwksUriOverride,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::TokenEndpointOverride,
                )),
                ProviderLookupIden::TokenEndpointOverride,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::AuthorizationEndpointOverride,
                )),
                ProviderLookupIden::AuthorizationEndpointOverride,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::UserinfoEndpointOverride,
                )),
                ProviderLookupIden::UserinfoEndpointOverride,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::DiscoveryMode,
                )),
                ProviderLookupIden::DiscoveryMode,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::PkceMode,
                )),
                ProviderLookupIden::PkceMode,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::ResponseMode,
                )),
                ProviderLookupIden::ResponseMode,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::AdditionalParameters,
                )),
                ProviderLookupIden::AdditionalParameters,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::ForwardLoginHint,
                )),
                ProviderLookupIden::ForwardLoginHint,
            )
            .expr_as(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::OnBackchannelLogout,
                )),
                ProviderLookupIden::OnBackchannelLogout,
            )
            .from(UpstreamOAuthProviders::Table)
            .apply_filter(filter)
            .generate_pagination(
                (
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::UpstreamOAuthProviderId,
                ),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let edges: Vec<ProviderLookup> = sqlx::query_as_with(&sql, arguments)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?;

        let page = pagination
            .process(edges)
            .try_map(UpstreamOAuthProvider::try_from)?;

        return Ok(page);
    }

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.count",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn count(
        &mut self,
        filter: UpstreamOAuthProviderFilter<'_>,
    ) -> Result<usize, Self::Error> {
        let (sql, arguments) = Query::select()
            .expr(
                Expr::col((
                    UpstreamOAuthProviders::Table,
                    UpstreamOAuthProviders::UpstreamOAuthProviderId,
                ))
                .count(),
            )
            .from(UpstreamOAuthProviders::Table)
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

    #[tracing::instrument(
        name = "db.upstream_oauth_provider.all_enabled",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn all_enabled(&mut self) -> Result<Vec<UpstreamOAuthProvider>, Self::Error> {
        let res = sqlx::query_as!(
            ProviderLookup,
            r#"
                SELECT
                    upstream_oauth_provider_id,
                    issuer,
                    human_name,
                    brand_name,
                    scope,
                    client_id,
                    encrypted_client_secret,
                    token_endpoint_signing_alg,
                    token_endpoint_auth_method,
                    id_token_signed_response_alg,
                    fetch_userinfo,
                    userinfo_signed_response_alg,
                    created_at,
                    disabled_at,
                    claims_imports as "claims_imports: Json<UpstreamOAuthProviderClaimsImports>",
                    jwks_uri_override,
                    authorization_endpoint_override,
                    token_endpoint_override,
                    userinfo_endpoint_override,
                    discovery_mode,
                    pkce_mode,
                    response_mode,
                    additional_parameters as "additional_parameters: Json<Vec<(String, String)>>",
                    forward_login_hint,
                    on_backchannel_logout
                FROM upstream_oauth_providers
                WHERE disabled_at IS NULL
                ORDER BY ui_order ASC, upstream_oauth_provider_id ASC
            "#,
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        let res: Result<Vec<_>, _> = res.into_iter().map(TryInto::try_into).collect();
        Ok(res?)
    }
}
