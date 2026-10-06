// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::num::NonZeroU64;

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::UserSessionLimitOverride,
        params::UlidPathParam,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

/// # JSON payload for the `PUT /api/admin/v1/user-session-limit-overrides/{id}`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "UpdateUserSessionLimitOverrideRequest")]
pub struct Request {
    /// Soft session limit
    soft_limit: NonZeroU64,

    /// Hard session limit
    hard_limit: NonZeroU64,
}

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User session limit override ID {0} not found")]
    NotFound(Ulid),

    #[error("hard_limit must be greater than or equal to soft_limit")]
    InvalidLimits,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidLimits => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("updateUserSessionLimitOverride")
        .summary("Update a user session limit override")
        .description(
            "Update the soft and hard limits of a per-user session limit override. \
             `max_session_threshold` and `dangerous_hard_limit_eviction` remain \
             determined by the YAML configuration.",
        )
        .tag("user-session-limit-override")
        .response_with::<200, Json<SingleResponse<UserSessionLimitOverride>>, _>(|t| {
            let [sample, ..] = UserSessionLimitOverride::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("User session limit override was updated")
                .example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::InvalidLimits);
            t.description("Limits are invalid").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User session limit override was not found")
                .example(response)
        })
}

#[tracing::instrument(
    name = "handler.admin.v1.user_session_limit_overrides.update",
    skip_all
)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    id: UlidPathParam,
    Json(params): Json<Request>,
) -> Result<Json<SingleResponse<UserSessionLimitOverride>>, RouteError> {
    if params.hard_limit < params.soft_limit {
        return Err(RouteError::InvalidLimits);
    }

    let override_row = repo
        .user_session_limit_override()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    let override_row = repo
        .user_session_limit_override()
        .set_limits(&clock, override_row, params.soft_limit, params.hard_limit)
        .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(override_row.into())))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use hyper::{Request, StatusCode};
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_update(pool: PgPool) {
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
        let override_row = repo
            .user_session_limit_override()
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
        let id = override_row.id;
        repo.save().await.unwrap();

        state.clock.advance(chrono::Duration::seconds(60));

        let request = Request::put(format!("/api/admin/v1/user-session-limit-overrides/{id}"))
            .bearer(&token)
            .json(serde_json::json!({
                "soft_limit": 8,
                "hard_limit": 10,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-session-limit-override",
            "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "updated_at": "2022-01-16T14:41:00Z",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "client_id": null,
              "soft_limit": 8,
              "hard_limit": 10
            },
            "links": {
              "self": "/api/admin/v1/user-session-limit-overrides/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-session-limit-overrides/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::put(format!(
            "/api/admin/v1/user-session-limit-overrides/{}",
            Ulid::nil()
        ))
        .bearer(&token)
        .json(serde_json::json!({
            "soft_limit": 8,
            "hard_limit": 10,
        }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invalid_limits(pool: PgPool) {
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
        let override_row = repo
            .user_session_limit_override()
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
        let id = override_row.id;
        repo.save().await.unwrap();

        let request = Request::put(format!("/api/admin/v1/user-session-limit-overrides/{id}"))
            .bearer(&token)
            .json(serde_json::json!({
                "soft_limit": 10,
                "hard_limit": 2,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
