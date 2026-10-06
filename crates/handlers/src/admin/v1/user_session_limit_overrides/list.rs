// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use axum_extra::extract::{Query, QueryRejection};
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{Page, user::UserSessionLimitOverrideFilter};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, UserSessionLimitOverride},
        params::{IncludeCount, Pagination},
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[serde(rename = "UserSessionLimitOverrideFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve the items for the given user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Retrieve the items for the given OAuth 2.0 client
    #[serde(rename = "filter[client]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    client: Option<Ulid>,

    /// When `true`, retrieve only global overrides (`client_id` is null)
    #[serde(rename = "filter[global]")]
    global: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(user) = self.user {
            write!(f, "{sep}filter[user]={user}")?;
            sep = '&';
        }

        if let Some(client) = self.client {
            write!(f, "{sep}filter[client]={client}")?;
            sep = '&';
        }

        if let Some(global) = self.global {
            write!(f, "{sep}filter[global]={global}")?;
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

    #[error("OAuth 2.0 client ID {0} not found")]
    ClientNotFound(Ulid),

    #[error("Cannot combine filter[global]=true with filter[client]")]
    ConflictingFilters,

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
            Self::UserNotFound(_) | Self::ClientNotFound(_) => StatusCode::NOT_FOUND,
            Self::ConflictingFilters | Self::InvalidFilter(_) => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("listUserSessionLimitOverrides")
        .summary("List user session limit overrides")
        .description("Retrieve a list of per-user session limit overrides.")
        .tag("user-session-limit-override")
        .response_with::<200, Json<PaginatedResponse<UserSessionLimitOverride>>, _>(|t| {
            let items = UserSessionLimitOverride::samples();
            let pagination = mas_storage::Pagination::first(items.len());
            let page = Page {
                edges: items
                    .into_iter()
                    .map(|node| mas_storage::pagination::Edge {
                        cursor: node.id(),
                        node,
                    })
                    .collect(),
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of user session limit overrides")
                .example(PaginatedResponse::for_page(
                    page,
                    pagination,
                    Some(42),
                    UserSessionLimitOverride::PATH,
                ))
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserNotFound(Ulid::nil()));
            t.description("User or OAuth 2.0 client was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_session_limit_overrides.list", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Pagination(pagination, include_count): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<UserSessionLimitOverride>>, RouteError> {
    if params.global == Some(true) && params.client.is_some() {
        return Err(RouteError::ConflictingFilters);
    }

    let base = format!("{path}{params}", path = UserSessionLimitOverride::PATH);
    let base = include_count.add_to_base(&base);
    let filter = UserSessionLimitOverrideFilter::default();

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

    let client = if let Some(client_id) = params.client {
        let client = repo
            .oauth2_client()
            .lookup(client_id)
            .await?
            .ok_or(RouteError::ClientNotFound(client_id))?;
        Some(client)
    } else {
        None
    };

    let filter = match &user {
        Some(user) => filter.for_user(user),
        None => filter,
    };

    let filter = match &client {
        Some(client) => filter.for_client(client),
        None => filter,
    };

    let filter = if params.global == Some(true) {
        filter.global_only()
    } else {
        filter
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .user_session_limit_override()
                .list(filter, pagination)
                .await?
                .map(UserSessionLimitOverride::from);
            let count = repo.user_session_limit_override().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .user_session_limit_override()
                .list(filter, pagination)
                .await?
                .map(UserSessionLimitOverride::from);
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.user_session_limit_override().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use hyper::{Request, StatusCode};
    use oauth2_types::requests::GrantType;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

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
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &state.clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        repo.user_session_limit_override()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                None,
                NonZeroU64::new(3).unwrap(),
                NonZeroU64::new(5).unwrap(),
            )
            .await
            .unwrap();
        repo.user_session_limit_override()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                Some(client.id),
                NonZeroU64::new(2).unwrap(),
                NonZeroU64::new(4).unwrap(),
            )
            .await
            .unwrap();
        repo.user_session_limit_override()
            .add(
                &mut rng,
                &state.clock,
                &bob,
                None,
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(1).unwrap(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get("/api/admin/v1/user-session-limit-overrides")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 3);
        assert_eq!(body["data"].as_array().unwrap().len(), 3);

        let request = Request::get(format!(
            "/api/admin/v1/user-session-limit-overrides?filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 2);

        let request =
            Request::get("/api/admin/v1/user-session-limit-overrides?filter[global]=true")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 2);

        let request = Request::get(format!(
            "/api/admin/v1/user-session-limit-overrides?filter[client]={}",
            client.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 1);

        let request = Request::get("/api/admin/v1/user-session-limit-overrides?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 3);
    }
}
