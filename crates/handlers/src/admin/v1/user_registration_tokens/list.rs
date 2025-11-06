// Copyright 2025 New Vector Ltd.
// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use axum_extra::extract::{Query, QueryRejection};
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{Page, user::UserRegistrationTokenFilter};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, UserRegistrationToken},
        params::{IncludeCount, Pagination},
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[serde(rename = "RegistrationTokenFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve tokens that have (or have not) been used at least once
    #[serde(rename = "filter[used]")]
    used: Option<bool>,

    /// Retrieve tokens that are (or are not) revoked
    #[serde(rename = "filter[revoked]")]
    revoked: Option<bool>,

    /// Retrieve tokens that are (or are not) expired
    #[serde(rename = "filter[expired]")]
    expired: Option<bool>,

    /// Retrieve tokens that are (or are not) valid
    ///
    /// Valid means that the token has not expired, is not revoked, and has not
    /// reached its usage limit.
    #[serde(rename = "filter[valid]")]
    valid: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(used) = self.used {
            write!(f, "{sep}filter[used]={used}")?;
            sep = '&';
        }
        if let Some(revoked) = self.revoked {
            write!(f, "{sep}filter[revoked]={revoked}")?;
            sep = '&';
        }
        if let Some(expired) = self.expired {
            write!(f, "{sep}filter[expired]={expired}")?;
            sep = '&';
        }
        if let Some(valid) = self.valid {
            write!(f, "{sep}filter[valid]={valid}")?;
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
        .id("listUserRegistrationTokens")
        .summary("List user registration tokens")
        .tag("user-registration-token")
        .response_with::<200, Json<PaginatedResponse<UserRegistrationToken>>, _>(|t| {
            let tokens = UserRegistrationToken::samples();
            let pagination = mas_storage::Pagination::first(tokens.len());
            let page = Page {
                edges: tokens
                    .into_iter()
                    .map(|node| mas_storage::pagination::Edge {
                        cursor: node.id(),
                        node,
                    })
                    .collect(),
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of registration tokens")
                .example(PaginatedResponse::for_page(
                    page,
                    pagination,
                    Some(42),
                    UserRegistrationToken::PATH,
                ))
        })
}

#[tracing::instrument(name = "handler.admin.v1.registration_tokens.list", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    Pagination(pagination, include_count): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<UserRegistrationToken>>, RouteError> {
    let base = format!("{path}{params}", path = UserRegistrationToken::PATH);
    let base = include_count.add_to_base(&base);
    let now = clock.now();
    let mut filter = UserRegistrationTokenFilter::new(now);

    if let Some(used) = params.used {
        filter = filter.with_been_used(used);
    }

    if let Some(revoked) = params.revoked {
        filter = filter.with_revoked(revoked);
    }

    if let Some(expired) = params.expired {
        filter = filter.with_expired(expired);
    }

    if let Some(valid) = params.valid {
        filter = filter.with_valid(valid);
    }

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .user_registration_token()
                .list(filter, pagination)
                .await?
                .map(|token| UserRegistrationToken::new(token, now));
            let count = repo.user_registration_token().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .user_registration_token()
                .list(filter, pagination)
                .await?
                .map(|token| UserRegistrationToken::new(token, now));
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.user_registration_token().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::Clock as _;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn create_test_tokens(state: &mut TestState) {
        let mut repo = state.repository().await.unwrap();

        // Token 1: Never used, not revoked
        repo.user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "token_unused".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();

        // Token 2: Used, not revoked
        let token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "token_used".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();
        repo.user_registration_token()
            .use_token(&state.clock, token)
            .await
            .unwrap();

        // Token 3: Never used, revoked
        let token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "token_revoked".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();
        repo.user_registration_token()
            .revoke(&state.clock, token)
            .await
            .unwrap();

        // Token 4: Used, revoked
        let token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "token_used_revoked".to_owned(),
                Some(10),
                None,
            )
            .await
            .unwrap();
        let token = repo
            .user_registration_token()
            .use_token(&state.clock, token)
            .await
            .unwrap();
        repo.user_registration_token()
            .revoke(&state.clock, token)
            .await
            .unwrap();

        // Token 5: Expired token
        let expires_at = state.clock.now() - Duration::try_days(1).unwrap();
        repo.user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "token_expired".to_owned(),
                Some(5),
                Some(expires_at),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list_all_tokens(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_tokens(&mut state).await;

        let request = Request::get("/api/admin/v1/user-registration-tokens")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=10"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_used(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_tokens(&mut state).await;

        // Filter for used tokens
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[used]=true")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[used]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[used]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[used]=true&page[last]=10"
          }
        }
        "#);

        // Filter for unused tokens
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[used]=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[used]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[used]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[used]=false&page[last]=10"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_revoked(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_tokens(&mut state).await;

        // Filter for revoked tokens
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[revoked]=true")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&page[last]=10"
          }
        }
        "#);

        // Filter for non-revoked tokens
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[revoked]=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[revoked]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[revoked]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[revoked]=false&page[last]=10"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_expired(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_tokens(&mut state).await;

        // Filter for expired tokens
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[expired]=true")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[expired]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[expired]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[expired]=true&page[last]=10"
          }
        }
        "#);

        // Filter for non-expired tokens
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[expired]=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 4
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[expired]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[expired]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[expired]=false&page[last]=10"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_valid(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_tokens(&mut state).await;

        // Filter for valid tokens
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[valid]=true")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[valid]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[valid]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[valid]=true&page[last]=10"
          }
        }
        "#);

        // Filter for invalid tokens
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[valid]=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[valid]=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[valid]=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[valid]=false&page[last]=10"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_combined_filters(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_tokens(&mut state).await;

        // Filter for used AND revoked tokens
        let request = Request::get(
            "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true",
        )
        .bearer(&admin_token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[used]=true&filter[revoked]=true&page[last]=10"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_pagination(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_tokens(&mut state).await;

        // Request with pagination (2 per page)
        let request = Request::get("/api/admin/v1/user-registration-tokens?page[first]=2")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[first]=2",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=2",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=2",
            "next": "/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2"
          }
        }
        "#);

        // Request second page
        let request = Request::get("/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG07HNEZXNQM2KNBNF6&page[first]=2",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=2",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=2",
            "next": "/api/admin/v1/user-registration-tokens?page[after]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=2"
          }
        }
        "#);

        // Request last item
        let request = Request::get("/api/admin/v1/user-registration-tokens?page[last]=1")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?page[last]=1",
            "first": "/api/admin/v1/user-registration-tokens?page[first]=1",
            "last": "/api/admin/v1/user-registration-tokens?page[last]=1",
            "prev": "/api/admin/v1/user-registration-tokens?page[before]=01FSHN9AG0S3ZJD8CXQ7F11KXN&page[last]=1"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invalid_filter(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;

        // Try with invalid filter value
        let request = Request::get("/api/admin/v1/user-registration-tokens?filter[used]=invalid")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let body: serde_json::Value = response.json();
        assert!(
            body["errors"][0]["title"]
                .as_str()
                .unwrap()
                .contains("Invalid filter parameters")
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_count_parameter(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;
        create_test_tokens(&mut state).await;

        // Test count=false
        let request = Request::get("/api/admin/v1/user-registration-tokens?count=false")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG064K8BYZXSY5G511Z",
              "attributes": {
                "token": "token_expired",
                "valid": false,
                "usage_limit": 5,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": "2022-01-15T14:40:00Z",
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG064K8BYZXSY5G511Z"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG064K8BYZXSY5G511Z"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG09AVTNSQFMSR34AJC",
              "attributes": {
                "token": "token_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG09AVTNSQFMSR34AJC"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG09AVTNSQFMSR34AJC"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0S3ZJD8CXQ7F11KXN",
              "attributes": {
                "token": "token_used_revoked",
                "valid": false,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": "2022-01-16T14:40:00Z"
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0S3ZJD8CXQ7F11KXN"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0S3ZJD8CXQ7F11KXN"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?count=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?count=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/user-registration-tokens?count=only")
            .bearer(&admin_token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 5
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?count=only"
          }
        }
        "#);

        // Test count=false with filtering
        let request =
            Request::get("/api/admin/v1/user-registration-tokens?count=false&filter[valid]=true")
                .bearer(&admin_token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
              "attributes": {
                "token": "token_used",
                "valid": true,
                "usage_limit": 10,
                "times_used": 1,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": "2022-01-16T14:40:00Z",
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG07HNEZXNQM2KNBNF6"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG07HNEZXNQM2KNBNF6"
                }
              }
            },
            {
              "type": "user-registration_token",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "token": "token_unused",
                "valid": true,
                "usage_limit": 10,
                "times_used": 0,
                "created_at": "2022-01-16T14:40:00Z",
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": null
              },
              "links": {
                "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[valid]=true&count=false&page[first]=10",
            "first": "/api/admin/v1/user-registration-tokens?filter[valid]=true&count=false&page[first]=10",
            "last": "/api/admin/v1/user-registration-tokens?filter[valid]=true&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request =
            Request::get("/api/admin/v1/user-registration-tokens?count=only&filter[revoked]=true")
                .bearer(&admin_token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens?filter[revoked]=true&count=only"
          }
        }
        "#);
    }
}
