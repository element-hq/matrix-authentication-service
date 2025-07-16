// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
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

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("unlockUser")
        .summary("Unlock a user")
        .description("Calling this endpoint will lift restrictions on user actions that had imposed by locking.
This DOES NOT reactivate a deactivated user, which will remain unavailable until it is explicitly reactivated.")
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
    id: UlidPathParam,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let id = *id;
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    let user = repo.user().unlock(user).await?;

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

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unlock_deactivated_user(pool: PgPool) {
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
        // The user should remain deactivated
        assert_eq!(
            body["data"]["attributes"]["deactivated_at"],
            serde_json::json!(state.clock.now())
        );
        let mx_user = state.homeserver_connection.query_user(&mxid).await.unwrap();
        assert!(mx_user.deactivated);
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
