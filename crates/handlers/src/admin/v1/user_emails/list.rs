// Copyright 2024, 2025 New Vector Ltd.
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
use mas_storage::{Page, user::UserEmailFilter};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, UserEmail},
        params::{IncludeCount, Pagination},
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[serde(rename = "UserEmailFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve the items for the given user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Retrieve the user email with the given email address
    #[serde(rename = "filter[email]")]
    email: Option<String>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(user) = self.user {
            write!(f, "{sep}filter[user]={user}")?;
            sep = '&';
        }

        if let Some(email) = &self.email {
            write!(f, "{sep}filter[email]={email}")?;
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
            Self::UserNotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidFilter(_) => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("listUserEmails")
        .summary("List user emails")
        .description("Retrieve a list of user emails.")
        .tag("user-email")
        .response_with::<200, Json<PaginatedResponse<UserEmail>>, _>(|t| {
            let emails = UserEmail::samples();
            let pagination = mas_storage::Pagination::first(emails.len());
            let page = Page {
                edges: emails.into(),
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of user emails")
                .example(PaginatedResponse::for_page(
                    page,
                    pagination,
                    Some(42),
                    UserEmail::PATH,
                ))
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserNotFound(Ulid::nil()));
            t.description("User was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_emails.list", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Pagination(pagination, include_count): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<UserEmail>>, RouteError> {
    let base = format!("{path}{params}", path = UserEmail::PATH);
    let base = include_count.add_to_base(&base);
    let filter = UserEmailFilter::default();

    // Load the user from the filter
    let user = if let Some(user_id) = params.user {
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or(RouteError::UserNotFound(user_id))?;

        Some(user)
    } else {
        None
    };

    let filter = match &user {
        Some(user) => filter.for_user(user),
        None => filter,
    };

    let filter = match &params.email {
        Some(email) => filter.for_email(email),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .user_email()
                .list(filter, pagination)
                .await?
                .map(UserEmail::from);
            let count = repo.user_email().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .user_email()
                .list(filter, pagination)
                .await?
                .map(UserEmail::from);
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.user_email().count(filter).await?;
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
    async fn test_list(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision two users, two emails
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

        repo.user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();
        repo.user_email()
            .add(&mut rng, &state.clock, &bob, "bob@example.com".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get("/api/admin/v1/user-emails")
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
          "data": [
            {
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              }
            },
            {
              "type": "user-email",
              "id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "email": "bob@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG0KEPHYQQXW9XPTX6Z"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-emails?page[first]=10",
            "first": "/api/admin/v1/user-emails?page[first]=10",
            "last": "/api/admin/v1/user-emails?page[last]=10"
          }
        }
        "###);

        // Filter by user
        let request = Request::get(format!(
            "/api/admin/v1/user-emails?filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "first": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "last": "/api/admin/v1/user-emails?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[last]=10"
          }
        }
        "###);

        // Filter by email
        let request = Request::get("/api/admin/v1/user-emails?filter[email]=alice@example.com")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "user-email",
              "id": "01FSHN9AG09NMZYX8MFYH578R9",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "email": "alice@example.com"
              },
              "links": {
                "self": "/api/admin/v1/user-emails/01FSHN9AG09NMZYX8MFYH578R9"
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/user-emails?filter[email]=alice@example.com&page[first]=10",
            "first": "/api/admin/v1/user-emails?filter[email]=alice@example.com&page[first]=10",
            "last": "/api/admin/v1/user-emails?filter[email]=alice@example.com&page[last]=10"
          }
        }
        "###);
    }
}
