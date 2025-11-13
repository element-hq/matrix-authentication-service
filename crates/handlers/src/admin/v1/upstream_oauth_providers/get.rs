// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{RepositoryAccess, upstream_oauth2::UpstreamOAuthProviderRepository};

use crate::{
    admin::{
        call_context::CallContext,
        model::UpstreamOAuthProvider,
        params::UlidPathParam,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Provider not found")]
    NotFound,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound => StatusCode::NOT_FOUND,
        };

        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("getUpstreamOAuthProvider")
        .summary("Get upstream OAuth provider")
        .tag("upstream-oauth-provider")
        .response_with::<200, Json<SingleResponse<UpstreamOAuthProvider>>, _>(|t| {
            let [sample, ..] = UpstreamOAuthProvider::samples();
            t.description("The upstream OAuth provider")
                .example(SingleResponse::new_canonical(sample))
        })
        .response_with::<404, Json<ErrorResponse>, _>(|t| t.description("Provider not found"))
}

#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.get", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<UpstreamOAuthProvider>>, RouteError> {
    let provider = repo
        .upstream_oauth_provider()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound)?;

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthProvider::from(provider),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_data_model::{
        UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_storage::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
    };
    use oauth2_types::scope::{OPENID, Scope};
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn create_test_provider(state: &mut TestState) -> UpstreamOAuthProvider {
        let mut repo = state.repository().await.unwrap();

        let params = UpstreamOAuthProviderParams {
            issuer: Some("https://accounts.google.com".to_owned()),
            human_name: Some("Google".to_owned()),
            brand_name: Some("google".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "google-client-id".to_owned(),
            encrypted_client_secret: Some("encrypted-secret".to_owned()),
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            response_mode: None,
            scope: Scope::from_iter([OPENID]),
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            additional_authorization_parameters: vec![],
            forward_login_hint: false,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            ui_order: 0,
        };

        let provider = repo
            .upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, params)
            .await
            .unwrap();

        Box::new(repo).save().await.unwrap();

        provider
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_provider(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        let provider = create_test_provider(&mut state).await;

        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-providers/{}",
            provider.id
        ))
        .bearer(&admin_token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        assert_eq!(body["data"]["type"], "upstream-oauth-provider");
        assert_eq!(body["data"]["id"], provider.id.to_string());
        assert_eq!(body["data"]["attributes"]["human_name"], "Google");

        insta::assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-provider",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "issuer": "https://accounts.google.com",
              "human_name": "Google",
              "brand_name": "google",
              "created_at": "2022-01-16T14:40:00Z",
              "disabled_at": null
            },
            "links": {
              "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "###);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;

        let provider_id = Ulid::nil();
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-providers/{provider_id}"
        ))
        .bearer(&admin_token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
