// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{
    Json,
    extract::{Query, rejection::QueryRejection},
    response::IntoResponse,
};
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{Page, user::UserFilter};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, User},
        params::{IncludeCount, Pagination},
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum UserStatus {
    Active,
    Locked,
    Deactivated,
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Locked => write!(f, "locked"),
            Self::Deactivated => write!(f, "deactivated"),
        }
    }
}

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[serde(rename = "UserFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve users with (or without) the `admin` flag set
    #[serde(rename = "filter[admin]")]
    admin: Option<bool>,

    /// Retrieve users with (or without) the `legacy_guest` flag set
    #[serde(rename = "filter[legacy-guest]")]
    legacy_guest: Option<bool>,

    /// Retrieve users where the username matches contains the given string
    ///
    /// Note that this doesn't change the ordering of the result, which are
    /// still ordered by ID.
    #[serde(rename = "filter[search]")]
    search: Option<String>,

    /// Retrieve the items with the given status
    ///
    /// Defaults to retrieve all users, including locked ones.
    ///
    /// * `active`: Only retrieve active users
    ///
    /// * `locked`: Only retrieve locked users (includes deactivated users)
    ///
    /// * `deactivated`: Only retrieve deactivated users
    #[serde(rename = "filter[status]")]
    status: Option<UserStatus>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(admin) = self.admin {
            write!(f, "{sep}filter[admin]={admin}")?;
            sep = '&';
        }
        if let Some(legacy_guest) = self.legacy_guest {
            write!(f, "{sep}filter[legacy-guest]={legacy_guest}")?;
            sep = '&';
        }
        if let Some(search) = &self.search {
            write!(f, "{sep}filter[search]={search}")?;
            sep = '&';
        }
        if let Some(status) = self.status {
            write!(f, "{sep}filter[status]={status}")?;
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
        .id("listUsers")
        .summary("List users")
        .tag("user")
        .response_with::<200, Json<PaginatedResponse<User>>, _>(|t| {
            let users = User::samples();
            let pagination = mas_storage::Pagination::first(users.len());
            let page = Page {
                edges: users.into(),
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of users")
                .example(PaginatedResponse::for_page(
                    page,
                    pagination,
                    Some(42),
                    User::PATH,
                ))
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.list", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Pagination(pagination, include_count): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<User>>, RouteError> {
    let base = format!("{path}{params}", path = User::PATH);
    let base = include_count.add_to_base(&base);
    let filter = UserFilter::default();

    let filter = match params.admin {
        Some(true) => filter.can_request_admin_only(),
        Some(false) => filter.cannot_request_admin_only(),
        None => filter,
    };

    let filter = match params.legacy_guest {
        Some(true) => filter.guest_only(),
        Some(false) => filter.non_guest_only(),
        None => filter,
    };

    let filter = match params.search.as_deref() {
        Some(search) => filter.matching_search(search),
        None => filter,
    };

    let filter = match params.status {
        Some(UserStatus::Active) => filter.active_only(),
        Some(UserStatus::Locked) => filter.locked_only(),
        Some(UserStatus::Deactivated) => filter.deactivated_only(),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo.user().list(filter, pagination).await?;
            let count = repo.user().count(filter).await?;
            PaginatedResponse::for_page(page.map(User::from), pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo.user().list(filter, pagination).await?;
            PaginatedResponse::for_page(page.map(User::from), pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.user().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list_users(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision two users
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Test default behavior (count=true)
        let request = Request::get("/api/admin/v1/users").bearer(&token).empty();
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
              "type": "user",
              "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "attributes": {
                "username": "bob",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
              }
            },
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/users?page[first]=10",
            "first": "/api/admin/v1/users?page[first]=10",
            "last": "/api/admin/v1/users?page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/api/admin/v1/users?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "attributes": {
                "username": "bob",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
              }
            },
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/users?count=false&page[first]=10",
            "first": "/api/admin/v1/users?count=false&page[first]=10",
            "last": "/api/admin/v1/users?count=false&page[last]=10"
          }
        }
        "###);

        // Test count=only
        let request = Request::get("/api/admin/v1/users?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/api/admin/v1/users?count=only"
          }
        }
        "###);

        // Test count=false with filtering
        let request = Request::get("/api/admin/v1/users?count=false&filter[search]=alice")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/users?filter[search]=alice&count=false&page[first]=10",
            "first": "/api/admin/v1/users?filter[search]=alice&count=false&page[first]=10",
            "last": "/api/admin/v1/users?filter[search]=alice&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get("/api/admin/v1/users?count=only&filter[search]=alice")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/api/admin/v1/users?filter[search]=alice&count=only"
          }
        }
        "#);
    }
}
