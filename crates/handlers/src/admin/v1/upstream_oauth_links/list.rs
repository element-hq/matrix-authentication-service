// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{
    Json,
    extract::{Query, rejection::QueryRejection},
    response::IntoResponse,
};
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{Page, upstream_oauth2::UpstreamOAuthLinkFilter};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, UpstreamOAuthLink},
        params::Pagination,
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[serde(rename = "UpstreamOAuthLinkFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve the items for the given user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Retrieve the items for the given provider
    #[serde(rename = "filter[provider]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    provider: Option<Ulid>,

    /// Retrieve the items with the given subject
    #[serde(rename = "filter[subject]")]
    subject: Option<String>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(user) = self.user {
            write!(f, "{sep}filter[user]={user}")?;
            sep = '&';
        }

        if let Some(provider) = self.provider {
            write!(f, "{sep}filter[provider]={provider}")?;
            sep = '&';
        }

        if let Some(subject) = &self.subject {
            write!(f, "{sep}filter[subject]={subject}")?;
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

    #[error("User ID {0} not found")]
    UserNotFound(Ulid),

    #[error("Provider ID {0} not found")]
    ProviderNotFound(Ulid),

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
            Self::UserNotFound(_) | Self::ProviderNotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidFilter(_) => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("listUpstreamOAuthLinks")
        .summary("List upstream OAuth 2.0 links")
        .description("Retrieve a list of upstream OAuth 2.0 links.")
        .tag("upstream-oauth-link")
        .response_with::<200, Json<PaginatedResponse<UpstreamOAuthLink>>, _>(|t| {
            let links = UpstreamOAuthLink::samples();
            let pagination = mas_storage::Pagination::first(links.len());
            let page = Page {
                edges: links.into(),
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of upstream OAuth 2.0 links")
                .example(PaginatedResponse::new(
                    page,
                    pagination,
                    42,
                    UpstreamOAuthLink::PATH,
                ))
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserNotFound(Ulid::nil()));
            t.description("User or provider was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.list", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Pagination(pagination): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<UpstreamOAuthLink>>, RouteError> {
    let base = format!("{path}{params}", path = UpstreamOAuthLink::PATH);
    let filter = UpstreamOAuthLinkFilter::default();

    // Load the user from the filter
    let maybe_user = if let Some(user_id) = params.user {
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or(RouteError::UserNotFound(user_id))?;
        Some(user)
    } else {
        None
    };

    let filter = if let Some(user) = &maybe_user {
        filter.for_user(user)
    } else {
        filter
    };

    // Load the provider from the filter
    let maybe_provider = if let Some(provider_id) = params.provider {
        let provider = repo
            .upstream_oauth_provider()
            .lookup(provider_id)
            .await?
            .ok_or(RouteError::ProviderNotFound(provider_id))?;
        Some(provider)
    } else {
        None
    };

    let filter = if let Some(provider) = &maybe_provider {
        filter.for_provider(provider)
    } else {
        filter
    };

    let filter = if let Some(subject) = &params.subject {
        filter.for_subject(subject)
    } else {
        filter
    };

    let page = repo.upstream_oauth_link().list(filter, pagination).await?;
    let count = repo.upstream_oauth_link().count(filter).await?;

    Ok(Json(PaginatedResponse::new(
        page.map(UpstreamOAuthLink::from),
        pagination,
        count,
        &base,
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;

    use super::super::test_utils;
    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision users and providers
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();
        let provider1 = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("acme"),
            )
            .await
            .unwrap();
        let provider2 = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("example"),
            )
            .await
            .unwrap();

        // Create some links
        let link1 = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider1,
                "subject1".to_owned(),
                Some("alice@acme".to_owned()),
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link1, &alice)
            .await
            .unwrap();
        let link2 = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider2,
                "subject2".to_owned(),
                Some("alice@example".to_owned()),
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link2, &alice)
            .await
            .unwrap();
        let link3 = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider1,
                "subject3".to_owned(),
                Some("bob@acme".to_owned()),
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link3, &bob)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?page[last]=10"
          }
        }
        "###);

        // Filter by user ID
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-links?filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[last]=10"
          }
        }
        "###);

        // Filter by provider
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-links?filter[provider]={}",
            provider1.id
        ))
        .bearer(&token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[last]=10"
          }
        }
        "###);

        // Filter by subject
        let request = Request::get(format!(
            "/api/admin/v1/upstream-oauth-links?filter[subject]={}",
            "subject1"
        ))
        .bearer(&token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links?filter[subject]=subject1&page[first]=10",
            "first": "/api/admin/v1/upstream-oauth-links?filter[subject]=subject1&page[first]=10",
            "last": "/api/admin/v1/upstream-oauth-links?filter[subject]=subject1&page[last]=10"
          }
        }
        "###);
    }
}
