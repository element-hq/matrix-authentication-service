// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

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

/// # JSON payload for the `POST /api/admin/v1/users/:id/set-admin` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "UserSetAdminRequest")]
pub struct Request {
    /// Whether the user can request admin privileges.
    admin: bool,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("userSetAdmin")
        .summary("Set whether a user can request admin")
        .description("Calling this endpoint will not have any effect on existing sessions, meaning that their existing sessions will keep admin access if they were granted it.")
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            // In the samples, the second user is the one which can request admin
            let [_alice, bob, ..] = User::samples();
            let id = bob.id();
            let response = SingleResponse::new(bob, format!("/api/admin/v1/users/{id}/set-admin"));
            t.description("User had admin privileges set").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User ID not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.set_admin", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    id: UlidPathParam,
    Json(params): Json<Request>,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let id = *id;
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    let user = repo
        .user()
        .set_can_request_admin(user, params.admin)
        .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/set-admin"),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_storage::{RepositoryAccess, user::UserRepository};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_change_can_request_admin(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post(format!("/api/admin/v1/users/{}/set-admin", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "admin": true,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["attributes"]["admin"], true);

        // Look at the state from the repository
        let mut repo = state.repository().await.unwrap();
        let user = repo.user().lookup(user.id).await.unwrap().unwrap();
        assert!(user.can_request_admin);
        repo.save().await.unwrap();

        // Flip it back
        let request = Request::post(format!("/api/admin/v1/users/{}/set-admin", user.id))
            .bearer(&token)
            .json(serde_json::json!({
                "admin": false,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["attributes"]["admin"], false);

        // Look at the state from the repository
        let mut repo = state.repository().await.unwrap();
        let user = repo.user().lookup(user.id).await.unwrap().unwrap();
        assert!(!user.can_request_admin);
        repo.save().await.unwrap();
    }
}
