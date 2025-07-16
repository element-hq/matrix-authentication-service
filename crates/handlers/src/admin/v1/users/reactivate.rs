// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, extract::State, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_matrix::HomeserverConnection;
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

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("reactivateUser")
        .summary("Reactivate a user")
        .description("Calling this endpoint will reactivate a deactivated user.
This DOES NOT unlock a locked user, which is still prevented from doing any action until it is explicitly unlocked.")
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            // In the samples, the third user is the one locked
            let [sample, ..] = User::samples();
            let id = sample.id();
            let response = SingleResponse::new(sample, format!("/api/admin/v1/users/{id}/reactivate"));
            t.description("User was reactivated").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User ID not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.reactivate", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let id = *id;
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    // Call the homeserver synchronously to reactivate the user
    let mxid = homeserver.mxid(&user.username);
    homeserver
        .reactivate_user(&mxid)
        .await
        .map_err(RouteError::Homeserver)?;

    // Now reactivate the user in our database
    let user = repo.user().reactivate(user).await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/reactivate"),
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
    async fn test_reactivate_deactivated_user(pool: PgPool) {
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
        let user = repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Provision and immediately deactivate the user on the homeserver,
        // because this endpoint will try to reactivate it
        let mxid = state.homeserver_connection.mxid(&user.username);
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&mxid, &user.sub))
            .await
            .unwrap();
        state
            .homeserver_connection
            .delete_user(&mxid, true)
            .await
            .unwrap();

        // The user should be deactivated on the homeserver
        let mx_user = state.homeserver_connection.query_user(&mxid).await.unwrap();
        assert!(mx_user.deactivated);

        let request = Request::post(format!("/api/admin/v1/users/{}/reactivate", user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The user should remain locked after being reactivated
        assert_eq!(
            body["data"]["attributes"]["locked_at"],
            serde_json::json!(state.clock.now())
        );
        assert_eq!(
            body["data"]["attributes"]["deactivated_at"],
            serde_json::Value::Null,
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_reactivate_active_user(pool: PgPool) {
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

        // Provision the user on the homeserver
        let mxid = state.homeserver_connection.mxid(&user.username);
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&mxid, &user.sub))
            .await
            .unwrap();

        let request = Request::post(format!("/api/admin/v1/users/{}/reactivate", user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["locked_at"],
            serde_json::Value::Null
        );
        assert_eq!(
            body["data"]["attributes"]["deactivated_at"],
            serde_json::Value::Null
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_reactivate_unknown_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/reactivate")
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
