// Copyright 2025 New Vector Ltd.
// Copyright 2025 The Matrix.org Foundation C.I.C.
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
        model::UserRegistrationToken,
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
        .id("getUserRegistrationToken")
        .summary("Get a user registration token")
        .tag("user-registration-token")
        .response_with::<200, Json<SingleResponse<UserRegistrationToken>>, _>(|t| {
            let [sample, ..] = UserRegistrationToken::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("Registration token was found")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("Registration token was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.get", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<UserRegistrationToken>>, RouteError> {
    let token = repo
        .user_registration_token()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    Ok(Json(SingleResponse::new_canonical(
        UserRegistrationToken::new(token, clock.now()),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        let registration_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                "test_token_123".to_owned(),
                Some(5),
                None,
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
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
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_nonexistent_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Use a fixed ID for the test to ensure consistent snapshots
        let nonexistent_id = Ulid::from_string("00000000000000000000000000").unwrap();
        let request = Request::get(format!(
            "/api/admin/v1/user-registration-tokens/{nonexistent_id}"
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Registration token with ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }
}
