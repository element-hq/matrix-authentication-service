// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, extract::State, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_matrix::HomeserverConnection;
use schemars::JsonSchema;
use serde::Deserialize;
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

    #[error(transparent)]
    Homeserver(anyhow::Error),

    #[error("User ID {0} not found")]
    NotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_) | Self::Homeserver(_));
        let status = match self {
            Self::Internal(_) | Self::Homeserver(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/users/:id/unlock` endpoint
#[derive(Default, Deserialize, JsonSchema)]
#[serde(rename = "UnlockUserRequest")]
pub struct Request {
    /// Whether to skip ensuring the user is active upon being unlocked.
    #[serde(default)]
    skip_reactivate: bool,
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
        .id("unlockUser")
        .summary("Unlock a user")
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            // In the samples, the third user is the one locked
            let [sample, ..] = User::samples();
            let id = sample.id();
            let response = SingleResponse::new(sample, format!("/api/admin/v1/users/{id}/unlock"));
            t.description("User was unlocked").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User ID not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.unlock", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    id: UlidPathParam,
    body: Option<Json<Request>>,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let Json(params) = body.unwrap_or_default();
    let id = *id;
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    let user = if params.skip_reactivate {
        repo.user().unlock(user).await?
    } else {
        // Call the homeserver synchronously to reactivate the user
        let mxid = homeserver.mxid(&user.username);
        homeserver
            .reactivate_user(&mxid)
            .await
            .map_err(RouteError::Homeserver)?;
        repo.user().reactivate_and_unlock(user).await?
    };

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/unlock"),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_matrix::{HomeserverConnection, ProvisionRequest};
    use mas_storage::{Clock, RepositoryAccess, user::UserRepository};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unlock_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let user = repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Also provision the user on the homeserver, because this endpoint will try to
        // reactivate it
        let mxid = state.homeserver_connection.mxid(&user.username);
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&mxid, &user.sub))
            .await
            .unwrap();

        let request = Request::post(format!("/api/admin/v1/users/{}/unlock", user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["locked_at"],
            serde_json::Value::Null
        );
    }

    async fn test_unlock_deactivated_user_helper(pool: PgPool, skip_reactivate: Option<bool>) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let user = repo.user().lock(&state.clock, user).await.unwrap();
        let user = repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Provision the user on the homeserver
        let mxid = state.homeserver_connection.mxid(&user.username);
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&mxid, &user.sub))
            .await
            .unwrap();
        // but then deactivate it
        state
            .homeserver_connection
            .delete_user(&mxid, true)
            .await
            .unwrap();

        // The user should be deactivated on the homeserver
        let mx_user = state.homeserver_connection.query_user(&mxid).await.unwrap();
        assert!(mx_user.deactivated);

        let request =
            Request::post(format!("/api/admin/v1/users/{}/unlock", user.id)).bearer(&token);
        let request = match skip_reactivate {
            None => request.empty(),
            Some(skip_reactivate) => request.json(serde_json::json!({
                "skip_reactivate": skip_reactivate,
            })),
        };
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["locked_at"],
            serde_json::Value::Null
        );

        let skip_reactivate = skip_reactivate.unwrap_or(false);
        assert_eq!(
            body["data"]["attributes"]["deactivated_at"],
            if skip_reactivate {
                serde_json::json!(state.clock.now())
            } else {
                serde_json::Value::Null
            }
        );

        // Check whether the user should be reactivated on the homeserver
        let mx_user = state.homeserver_connection.query_user(&mxid).await.unwrap();
        assert_eq!(mx_user.deactivated, skip_reactivate);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unlock_deactivated_user(pool: PgPool) {
        test_unlock_deactivated_user_helper(pool, Option::None).await;
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unlock_deactivated_user_skip_reactivate(pool: PgPool) {
        test_unlock_deactivated_user_helper(pool, Option::Some(true)).await;
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_lock_unknown_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/unlock")
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
