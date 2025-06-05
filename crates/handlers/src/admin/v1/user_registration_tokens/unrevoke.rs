// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, UserRegistrationToken},
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

    #[error("Registration token with ID {0} not found")]
    NotFound(Ulid),

    #[error("Registration token with ID {0} is not revoked")]
    NotRevoked(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::NotRevoked(_) => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("unrevokeUserRegistrationToken")
        .summary("Unrevoke a user registration token")
        .description("Calling this endpoint will unrevoke a previously revoked user registration token, allowing it to be used for registrations again (subject to its usage limits and expiration).")
        .tag("user-registration-token")
        .response_with::<200, Json<SingleResponse<UserRegistrationToken>>, _>(|t| {
            // Get the valid token sample
            let [valid_token, _] = UserRegistrationToken::samples();
            let id = valid_token.id();
            let response = SingleResponse::new(valid_token, format!("/api/admin/v1/user-registration-tokens/{id}/unrevoke"));
            t.description("Registration token was unrevoked").example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotRevoked(Ulid::nil()));
            t.description("Token is not revoked").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("Registration token was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.unrevoke", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<UserRegistrationToken>>, RouteError> {
    let id = *id;
    let token = repo
        .user_registration_token()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    // Check if the token is not revoked
    if token.revoked_at.is_none() {
        return Err(RouteError::NotRevoked(id));
    }

    // Unrevoke the token using the repository method
    let token = repo.user_registration_token().unrevoke(token).await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        UserRegistrationToken::new(token, clock.now()),
        format!("/api/admin/v1/user-registration-tokens/{id}/unrevoke"),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unrevoke_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();

        // Create a token
        let registration_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "test_token_456".to_owned(),
                Some(5),
                None,
            )
            .await
            .unwrap();

        // Revoke it
        let registration_token = repo
            .user_registration_token()
            .revoke(&state.clock, registration_token)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Now unrevoke it
        let request = Request::post(format!(
            "/api/admin/v1/user-registration-tokens/{}/unrevoke",
            registration_token.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The revoked_at timestamp should be null
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_456",
              "valid": true,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E/unrevoke"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unrevoke_not_revoked_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let registration_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "test_token_789".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Try to unrevoke a token that's not revoked
        let request = Request::post(format!(
            "/api/admin/v1/user-registration-tokens/{}/unrevoke",
            registration_token.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!(
                "Registration token with ID {} is not revoked",
                registration_token.id
            )
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unrevoke_unknown_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post(
            "/api/admin/v1/user-registration-tokens/01040G2081040G2081040G2081/unrevoke",
        )
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Registration token with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
