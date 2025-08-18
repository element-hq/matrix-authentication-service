// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, extract::State, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::BoxRng;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::{
    admin::{call_context::CallContext, params::UlidPathParam, response::ErrorResponse},
    impl_from_error_for_route,
    passwords::PasswordManager,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Password is too weak")]
    PasswordTooWeak,

    #[error("Password auth is disabled")]
    PasswordAuthDisabled,

    #[error("Password hashing failed")]
    Password(#[source] anyhow::Error),

    #[error("User ID {0} not found")]
    NotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_) | Self::Password(_));
        let status = match self {
            Self::Internal(_) | Self::Password(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::PasswordAuthDisabled => StatusCode::FORBIDDEN,
            Self::PasswordTooWeak => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

fn password_example() -> String {
    "hunter2".to_owned()
}

/// # JSON payload for the `POST /api/admin/v1/users/:id/set-password` endpoint
#[derive(Deserialize, JsonSchema)]
#[schemars(rename = "SetUserPasswordRequest")]
pub struct Request {
    /// The password to set for the user
    #[schemars(example = "password_example")]
    password: String,

    /// Skip the password complexity check
    skip_password_check: Option<bool>,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("setUserPassword")
        .summary("Set the password for a user")
        .tag("user")
        .response_with::<204, (), _>(|t| t.description("Password was set"))
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::PasswordTooWeak);
            t.description("Password is too weak").example(response)
        })
        .response_with::<403, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::PasswordAuthDisabled);
            t.description("Password auth is disabled in the server configuration")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.set_password", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    State(password_manager): State<PasswordManager>,
    id: UlidPathParam,
    Json(params): Json<Request>,
) -> Result<StatusCode, RouteError> {
    if !password_manager.is_enabled() {
        return Err(RouteError::PasswordAuthDisabled);
    }

    let user = repo
        .user()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    let skip_password_check = params.skip_password_check.unwrap_or(false);
    tracing::info!(skip_password_check, "skip_password_check");
    if !skip_password_check
        && !password_manager
            .is_password_complex_enough(&params.password)
            .unwrap_or(false)
    {
        return Err(RouteError::PasswordTooWeak);
    }

    let password = Zeroizing::new(params.password);
    let (version, hashed_password) = password_manager
        .hash(&mut rng, password)
        .await
        .map_err(RouteError::Password)?;

    repo.user_password()
        .add(&mut rng, &clock, &user, version, hashed_password, None)
        .await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_storage::{RepositoryAccess, user::UserPasswordRepository};
    use sqlx::PgPool;
    use zeroize::Zeroizing;

    use crate::{
        passwords::{PasswordManager, PasswordVerificationResult},
        test_utils::{RequestBuilderExt, ResponseExt, TestState, setup},
    };

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_set_password(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Create a user
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        // Double-check that the user doesn't have a password
        let user_password = repo.user_password().active(&user).await.unwrap();
        assert!(user_password.is_none());

        repo.save().await.unwrap();

        let user_id = user.id;

        // Set the password through the API
        let request = Request::post(format!("/api/admin/v1/users/{user_id}/set-password"))
            .bearer(&token)
            .json(serde_json::json!({
                "password": "this is a good enough password",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Check that the user now has a password
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap().unwrap();
        let password = Zeroizing::new(String::from("this is a good enough password"));
        let res = state
            .password_manager
            .verify(
                user_password.version,
                password,
                user_password.hashed_password,
            )
            .await
            .unwrap();
        assert_eq!(res, PasswordVerificationResult::Success(()));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_weak_password(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Create a user
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let user_id = user.id;

        // Set a weak password through the API
        let request = Request::post(format!("/api/admin/v1/users/{user_id}/set-password"))
            .bearer(&token)
            .json(serde_json::json!({
                "password": "password",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        // Check that the user still has a password
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap();
        assert!(user_password.is_none());
        repo.save().await.unwrap();

        // Now try with the skip_password_check flag
        let request = Request::post(format!("/api/admin/v1/users/{user_id}/set-password"))
            .bearer(&token)
            .json(serde_json::json!({
                "password": "password",
                "skip_password_check": true,
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Check that the user now has a password
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap().unwrap();
        let password = Zeroizing::new("password".to_owned());
        let res = state
            .password_manager
            .verify(
                user_password.version,
                password,
                user_password.hashed_password,
            )
            .await
            .unwrap();
        assert_eq!(res, PasswordVerificationResult::Success(()));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unknown_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Set the password through the API
        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/set-password")
            .bearer(&token)
            .json(serde_json::json!({
                "password": "this is a good enough password",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);

        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "User ID 01040G2081040G2081040G2081 not found"
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_disabled(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        state.password_manager = PasswordManager::disabled();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/set-password")
            .bearer(&token)
            .json(serde_json::json!({
                "password": "hunter2",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::FORBIDDEN);

        let body: serde_json::Value = response.json();
        assert_eq!(body["errors"][0]["title"], "Password auth is disabled");
    }
}
