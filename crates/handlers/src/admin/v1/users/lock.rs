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
        .id("lockUser")
        .summary("Lock a user")
        .description("Calling this endpoint will lock the user, preventing them from doing any action.
This DOES NOT invalidate any existing session, meaning that all their existing sessions will work again as soon as they get unlocked.")
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            // In the samples, the third user is the one locked
            let [_alice, _bob, charlie, ..] = User::samples();
            let id = charlie.id();
            let response = SingleResponse::new(charlie, format!("/api/admin/v1/users/{id}/lock"));
            t.description("User was locked").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User ID not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.lock", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let id = *id;
    let mut user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    if user.locked_at.is_none() {
        user = repo.user().lock(&clock, user).await?;
    }

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/lock"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_storage::{Clock, RepositoryAccess, user::UserRepository};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_lock_user(pool: PgPool) {
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

        let request = Request::post(format!("/api/admin/v1/users/{}/lock", user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The locked_at timestamp should be the same as the current time
        assert_eq!(
            body["data"]["attributes"]["locked_at"],
            serde_json::json!(state.clock.now())
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_lock_user_twice(pool: PgPool) {
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

        // Move the clock forward to make sure the locked_at timestamp doesn't change
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!("/api/admin/v1/users/{}/lock", user.id))
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
        assert_ne!(
            body["data"]["attributes"]["locked_at"],
            serde_json::Value::Null
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_lock_unknown_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/lock")
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
