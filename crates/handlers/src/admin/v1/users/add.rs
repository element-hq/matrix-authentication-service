// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use aide::{transform::TransformOperation, NoApi, OperationIo};
use axum::{extract::State, response::IntoResponse, Json};
use hyper::StatusCode;
use mas_matrix::BoxHomeserverConnection;
use mas_storage::{
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    BoxRng,
};
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::warn;

use crate::{
    admin::{
        call_context::CallContext,
        model::User,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

fn valid_username_character(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || c == '='
        || c == '_'
        || c == '-'
        || c == '.'
        || c == '/'
        || c == '+'
}

// XXX: this should be shared with the graphql handler
fn username_valid(username: &str) -> bool {
    if username.is_empty() || username.len() > 255 {
        return false;
    }

    // Should not start with an underscore
    if username.starts_with('_') {
        return false;
    }

    // Should only contain valid characters
    if !username.chars().all(valid_username_character) {
        return false;
    }

    true
}

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(transparent)]
    Homeserver(anyhow::Error),

    #[error("Username is not valid")]
    UsernameNotValid,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Username is reserved by the homeserver")]
    UsernameReserved,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let status = match self {
            Self::Internal(_) | Self::Homeserver(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UsernameNotValid => StatusCode::BAD_REQUEST,
            Self::UserAlreadyExists | Self::UsernameReserved => StatusCode::CONFLICT,
        };
        (status, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/users` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRequest")]
pub struct Request {
    /// The username of the user to add.
    username: String,

    /// Skip checking with the homeserver whether the username is available.
    ///
    /// Use this with caution! The main reason to use this, is when a user used
    /// by an application service needs to exist in MAS to craft special
    /// tokens (like with admin access) for them
    #[serde(default)]
    skip_homeserver_check: bool,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("createUser")
        .summary("Create a new user")
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            let [sample, ..] = User::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("User was created").example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UsernameNotValid);
            t.description("Username is not valid").example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserAlreadyExists);
            t.description("User already exists").example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UsernameReserved);
            t.description("Username is reserved by the homeserver")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.add", skip_all, err)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    State(homeserver): State<BoxHomeserverConnection>,
    Json(params): Json<Request>,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    if repo.user().exists(&params.username).await? {
        return Err(RouteError::UserAlreadyExists);
    }

    // Do some basic check on the username
    if !username_valid(&params.username) {
        return Err(RouteError::UsernameNotValid);
    }

    // Ask the homeserver if the username is available
    let homeserver_available = homeserver
        .is_localpart_available(&params.username)
        .await
        .map_err(RouteError::Homeserver)?;

    if !homeserver_available {
        if !params.skip_homeserver_check {
            return Err(RouteError::UsernameReserved);
        }

        // If we skipped the check, we still want to shout about it
        warn!("Skipped homeserver check for username {}", params.username);
    }

    let user = repo.user().add(&mut rng, &clock, params.username).await?;

    repo.queue_job()
        .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&user))
        .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(User::from(user))))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_storage::{user::UserRepository, RepositoryAccess};
    use sqlx::PgPool;

    use crate::test_utils::{setup, RequestBuilderExt, ResponseExt, TestState};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_add_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "alice",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "user");
        let id = body["data"]["id"].as_str().unwrap();
        assert_eq!(body["data"]["attributes"]["username"], "alice");

        // Check that the user was created in the database
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .lookup(id.parse().unwrap())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.username, "alice");
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_add_user_invalid_username(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "this is invalid",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "Username is not valid");
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_add_user_exists(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "alice",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "user");
        assert_eq!(body["data"]["attributes"]["username"], "alice");

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "alice",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "User already exists");
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_add_user_reserved(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Reserve a username on the homeserver and try to add it
        state.homeserver_connection.reserve_localpart("bob").await;

        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "bob",
            }));

        let response = state.request(request).await;

        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Username is reserved by the homeserver"
        );

        // But we can force it with the skip_homeserver_check flag
        let request = Request::post("/api/admin/v1/users")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "bob",
                "skip_homeserver_check": true,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let body: serde_json::Value = response.json();
        let id = body["data"]["id"].as_str().unwrap();
        assert_eq!(body["data"]["attributes"]["username"], "bob");

        // Check that the user was created in the database
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .lookup(id.parse().unwrap())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user.username, "bob");
    }
}
