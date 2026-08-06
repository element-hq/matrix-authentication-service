// Copyright 2026 BWI GmbH
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, extract::State, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_matrix::{HomeserverConnection, ProvisionRequest};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::User,
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
            RouteError::NotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `PUT /api/admin/v1/users/displayname` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "SetUserDisplaynameRequest")]
pub struct Request {
    /// The displayname of the user.
    displayname: String,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("setUserDisplayname")
        .summary("Set a user’s displayname")
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            let [sample, ..] = User::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("User displayname was updated")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.add", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    id: UlidPathParam,
    Json(params): Json<Request>,
) -> Result<StatusCode, RouteError> {
    let user = repo
        .user()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    let provision_request =
        ProvisionRequest::new(&user.username, &user.sub, false).set_displayname(params.displayname);

    homeserver
        .provision_user(&provision_request)
        .await
        .map_err(RouteError::Homeserver)?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_storage::RepositoryAccess;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_set_displayname(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Create a user
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "boaty".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let user_id = user.id;

        // Set the displayname through the API
        let request = Request::put(format!("/api/admin/v1/users/{user_id}/displayname"))
            .bearer(&token)
            .json(serde_json::json!({
                "displayname": "Boaty McBoatface",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unknown_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Set the displayname through the API
        let request = Request::put("/api/admin/v1/users/01040G2081040G2081040G2081/displayname")
            .bearer(&token)
            .json(serde_json::json!({
                "displayname": "Boaty McBoatface",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);

        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "User ID 01040G2081040G2081040G2081 not found"
        );
    }
}
