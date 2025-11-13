// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
<<<<<<< HEAD
use axum::{
    Json,
    extract::{Query, rejection::QueryRejection},
    response::IntoResponse,
};
=======
use axum::{Json, response::IntoResponse};
use axum_extra::extract::{Query, QueryRejection};
>>>>>>> v1.6.0
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{Page, upstream_oauth2::UpstreamOAuthProviderFilter};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, UpstreamOAuthProvider},
<<<<<<< HEAD
        params::Pagination,
=======
        params::{IncludeCount, Pagination},
>>>>>>> v1.6.0
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[serde(rename = "UpstreamOAuthProviderFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve providers that are (or are not) enabled
    #[serde(rename = "filter[enabled]")]
    enabled: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(enabled) = self.enabled {
            write!(f, "{sep}filter[enabled]={enabled}")?;
            sep = '&';
        }

        let _ = sep;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Invalid filter parameters")]
    InvalidFilter(#[from] QueryRejection),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidFilter(_) => StatusCode::BAD_REQUEST,
        };

        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("listUpstreamOAuthProviders")
        .summary("List upstream OAuth 2.0 providers")
        .tag("upstream-oauth-provider")
        .response_with::<200, Json<PaginatedResponse<UpstreamOAuthProvider>>, _>(|t| {
            let providers = UpstreamOAuthProvider::samples();
            let pagination = mas_storage::Pagination::first(providers.len());
            let page = Page {
<<<<<<< HEAD
                edges: providers.into(),
=======
                edges: providers
                    .into_iter()
                    .map(|node| mas_storage::pagination::Edge {
                        cursor: node.id(),
                        node,
                    })
                    .collect(),
>>>>>>> v1.6.0
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of upstream OAuth 2.0 providers")
<<<<<<< HEAD
                .example(PaginatedResponse::new(
                    page,
                    pagination,
                    42,
=======
                .example(PaginatedResponse::for_page(
                    page,
                    pagination,
                    Some(42),
>>>>>>> v1.6.0
                    UpstreamOAuthProvider::PATH,
                ))
        })
}

#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_providers.list", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
<<<<<<< HEAD
    Pagination(pagination): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<UpstreamOAuthProvider>>, RouteError> {
    let base = format!("{path}{params}", path = UpstreamOAuthProvider::PATH);
=======
    Pagination(pagination, include_count): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<UpstreamOAuthProvider>>, RouteError> {
    let base = format!("{path}{params}", path = UpstreamOAuthProvider::PATH);
    let base = include_count.add_to_base(&base);
>>>>>>> v1.6.0
    let filter = UpstreamOAuthProviderFilter::new();

    let filter = match params.enabled {
        Some(true) => filter.enabled_only(),
        Some(false) => filter.disabled_only(),
        None => filter,
    };

<<<<<<< HEAD
    let page = repo
        .upstream_oauth_provider()
        .list(filter, pagination)
        .await?;
    let count = repo.upstream_oauth_provider().count(filter).await?;

    Ok(Json(PaginatedResponse::new(
        page.map(UpstreamOAuthProvider::from),
        pagination,
        count,
        &base,
    )))
=======
    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .upstream_oauth_provider()
                .list(filter, pagination)
                .await?
                .map(UpstreamOAuthProvider::from);
            let count = repo.upstream_oauth_provider().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .upstream_oauth_provider()
                .list(filter, pagination)
                .await?
                .map(UpstreamOAuthProvider::from);
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.upstream_oauth_provider().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
>>>>>>> v1.6.0
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_data_model::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_storage::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
    };
    use oauth2_types::scope::{OPENID, Scope};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn create_test_providers(state: &mut TestState) {
        let mut repo = state.repository().await.unwrap();

        // Create an enabled provider
        let enabled_params = UpstreamOAuthProviderParams {
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

        repo.upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, enabled_params)
            .await
            .unwrap();

        // Create a disabled provider
        let disabled_params = UpstreamOAuthProviderParams {
            issuer: Some("https://appleid.apple.com".to_owned()),
            human_name: Some("Apple ID".to_owned()),
            brand_name: Some("apple".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::S256,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "apple-client-id".to_owned(),
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
            ui_order: 1,
        };

        let disabled_provider = repo
            .upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, disabled_params)
            .await
            .unwrap();

        // Disable the provider
        repo.upstream_oauth_provider()
            .disable(&state.clock, disabled_provider)
            .await
            .unwrap();

        // Create another enabled provider
        let another_enabled_params = UpstreamOAuthProviderParams {
            issuer: Some("https://login.microsoftonline.com/common/v2.0".to_owned()),
            human_name: Some("Microsoft".to_owned()),
            brand_name: Some("microsoft".to_owned()),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: true,
            userinfo_signed_response_alg: None,
            client_id: "microsoft-client-id".to_owned(),
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
            ui_order: 2,
        };

        repo.upstream_oauth_provider()
            .add(&mut state.rng(), &state.clock, another_enabled_params)
            .await
            .unwrap();

        Box::new(repo).save().await.unwrap();
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list_all_providers(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_providers(&mut state).await;

        let request = Request::get("/api/admin/v1/upstream-oauth-providers")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        // Should return all providers
        assert_eq!(body["data"].as_array().unwrap().len(), 3);

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
<<<<<<< HEAD
=======
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
>>>>>>> v1.6.0
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
<<<<<<< HEAD
=======
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
>>>>>>> v1.6.0
              }
            },
            {
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
<<<<<<< HEAD
=======
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
>>>>>>> v1.6.0
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?page[last]=10"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_enabled_true(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_providers(&mut state).await;

        let request = Request::get("/api/admin/v1/upstream-oauth-providers?filter[enabled]=true")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
<<<<<<< HEAD
=======
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
>>>>>>> v1.6.0
              }
            },
            {
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
<<<<<<< HEAD
=======
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
>>>>>>> v1.6.0
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&page[last]=10"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_enabled_false(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_providers(&mut state).await;

        let request = Request::get("/api/admin/v1/upstream-oauth-providers?filter[enabled]=false")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
<<<<<<< HEAD
=======
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
>>>>>>> v1.6.0
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=false&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=false&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=false&page[last]=10"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_pagination(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_providers(&mut state).await;

        // Test first page with limit of 2
        let request = Request::get("/api/admin/v1/upstream-oauth-providers?page[first]=2")
            .bearer(&admin_token)
            .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
<<<<<<< HEAD
=======
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
>>>>>>> v1.6.0
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
<<<<<<< HEAD
=======
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
>>>>>>> v1.6.0
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?page[first]=2",
            "first": "/api/admin/v1/upstream-oauth-providers?page[first]=2",
            "last": "/api/admin/v1/upstream-oauth-providers?page[last]=2",
            "next": "/api/admin/v1/upstream-oauth-providers?page[after]=01FSHN9AG09AVTNSQFMSR34AJC&page[first]=2"
          }
        }
        "#);

        // Extract the ID of the last item for pagination
        let last_item_id = body["data"][1]["id"].as_str().unwrap();
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-providers?page[first]=2&page[after]={last_item_id}",
        ))
        .bearer(&admin_token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
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
<<<<<<< HEAD
=======
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
>>>>>>> v1.6.0
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?page[after]=01FSHN9AG09AVTNSQFMSR34AJC&page[first]=2",
            "first": "/api/admin/v1/upstream-oauth-providers?page[first]=2",
            "last": "/api/admin/v1/upstream-oauth-providers?page[last]=2"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invalid_filter(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;

        let request =
            Request::get("/api/admin/v1/upstream-oauth-providers?filter[enabled]=invalid")
                .bearer(&admin_token)
                .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
<<<<<<< HEAD
=======

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_count_parameter(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_providers(&mut state).await;

        // Test count=false
        let request = Request::get("/api/admin/v1/upstream-oauth-providers?count=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "issuer": "https://appleid.apple.com",
                "human_name": "Apple ID",
                "brand_name": "apple",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?count=false&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?count=false&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/upstream-oauth-providers?count=only")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?count=only"
          }
        }
        "#);

        // Test count=false with filtering
        let request =
            Request::get("/api/admin/v1/upstream-oauth-providers?count=false&filter[enabled]=true")
                .bearer(&admin_token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-provider",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "issuer": "https://login.microsoftonline.com/common/v2.0",
                "human_name": "Microsoft",
                "brand_name": "microsoft",
                "created_at": "2022-01-16T14:40:00Z",
                "disabled_at": null
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-providers/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&count=false&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&count=false&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=true&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request =
            Request::get("/api/admin/v1/upstream-oauth-providers?count=only&filter[enabled]=false")
                .bearer(&admin_token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json::<serde_json::Value>();

        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-providers?filter[enabled]=false&count=only"
          }
        }
        "#);
    }
>>>>>>> v1.6.0
}
