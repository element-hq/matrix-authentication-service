// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{
    BoxRng,
    queue::{DeactivateUserJob, QueueJobRepositoryExt as _},
};
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::info;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, User},
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

    #[error("User ID {0} not found")]
    NotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/users/:id/deactivate` endpoint
#[derive(Default, Deserialize, JsonSchema)]
#[serde(rename = "DeactivateUserRequest")]
pub struct Request {
    /// Whether to skip requesting the homeserver to GDPR-erase the user upon
    /// deactivation.
    #[serde(default)]
    skip_erase: bool,
}

pub fn doc(mut operation: TransformOperation) -> TransformOperation {
    operation
        .inner_mut()
        .request_body
        .as_mut()
        .unwrap()
        .as_item_mut()
        .unwrap()
        .required = false;

    operation
        .id("deactivateUser")
        .summary("Deactivate a user")
        .description("Calling this endpoint will lock and deactivate the user, preventing them from doing any action.
This invalidates any existing session, and will ask the homeserver to make them leave all rooms.")
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            // In the samples, the third user is the one locked
            let [_alice, _bob, charlie, ..] = User::samples();
            let id = charlie.id();
            let response = SingleResponse::new(charlie, format!("/api/admin/v1/users/{id}/deactivate"));
            t.description("User was deactivated").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User ID not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.deactivate", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    id: UlidPathParam,
    body: Option<Json<Request>>,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let Json(params) = body.unwrap_or_default();
    let id = *id;
    let mut user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    if user.locked_at.is_none() {
        user = repo.user().lock(&clock, user).await?;
    }

    info!(%user.id, "Scheduling deactivation of user");
    repo.queue_job()
        .schedule_job(
            &mut rng,
            &clock,
            DeactivateUserJob::new(&user, !params.skip_erase),
        )
        .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/deactivate"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use insta::{allow_duplicates, assert_json_snapshot};
    use mas_storage::{Clock, RepositoryAccess, user::UserRepository};
    use sqlx::{PgPool, types::Json};

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn test_deactivate_user_helper(pool: PgPool, skip_erase: Option<bool>) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request =
            Request::post(format!("/api/admin/v1/users/{}/deactivate", user.id)).bearer(&token);
        let request = match skip_erase {
            None => request.empty(),
            Some(skip_erase) => request.json(serde_json::json!({
                "skip_erase": skip_erase,
            })),
        };
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The locked_at timestamp should be the same as the current time
        assert_eq!(
            body["data"]["attributes"]["locked_at"],
            serde_json::json!(state.clock.now())
        );

        // It should have scheduled a deactivation job for the user
        // XXX: we don't have a good way to look for the deactivation job
        let job: Json<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM queue_jobs WHERE queue_name = 'deactivate-user'",
        )
        .fetch_one(&pool)
        .await
        .expect("Deactivation job to be scheduled");
        assert_eq!(job["user_id"], serde_json::json!(user.id));
        assert_eq!(
            job["hs_erase"],
            serde_json::json!(!skip_erase.unwrap_or(false))
        );

        // Make sure to run the jobs in the queue
        state.run_jobs_in_queue().await;

        let request = Request::get(format!("/api/admin/v1/users/{}", user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        allow_duplicates!(assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "username": "alice",
              "created_at": "2022-01-16T14:40:00Z",
              "locked_at": "2022-01-16T14:40:00Z",
              "deactivated_at": "2022-01-16T14:40:00Z",
              "admin": false
            },
            "links": {
              "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deactivate_user(pool: PgPool) {
        test_deactivate_user_helper(pool, Option::None).await;
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deactivate_user_skip_erase(pool: PgPool) {
        test_deactivate_user_helper(pool, Option::Some(true)).await;
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deactivate_locked_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let user = repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Move the clock forward to make sure the locked_at timestamp doesn't change
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!("/api/admin/v1/users/{}/deactivate", user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The locked_at timestamp should be different from the current time
        assert_ne!(
            body["data"]["attributes"]["locked_at"],
            serde_json::json!(state.clock.now())
        );

        // Make sure to run the jobs in the queue
        state.run_jobs_in_queue().await;

        let request = Request::get(format!("/api/admin/v1/users/{}", user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "username": "alice",
              "created_at": "2022-01-16T14:40:00Z",
              "locked_at": "2022-01-16T14:40:00Z",
              "deactivated_at": "2022-01-16T14:41:00Z",
              "admin": false
            },
            "links": {
              "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deactivate_unknown_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/deactivate")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "User ID 01040G2081040G2081040G2081 not found"
        );
    }
}
