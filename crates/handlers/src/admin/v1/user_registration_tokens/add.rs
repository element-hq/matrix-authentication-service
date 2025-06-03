// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use chrono::{DateTime, Utc};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::BoxRng;
use rand::{Rng, distributions::Alphanumeric};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::CallContext,
        model::UserRegistrationToken,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/user-registration-tokens`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRegistrationTokenRequest")]
pub struct Request {
    /// The token string. If not provided, a random token will be generated.
    token: Option<String>,

    /// Maximum number of times this token can be used. If not provided, the
    /// token can be used an unlimited number of times.
    usage_limit: Option<u32>,

    /// When the token expires. If not provided, the token never expires.
    expires_at: Option<DateTime<Utc>>,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("addUserRegistrationToken")
        .summary("Create a new user registration token")
        .tag("user-registration-token")
        .response_with::<201, Json<SingleResponse<UserRegistrationToken>>, _>(|t| {
            let [sample, ..] = UserRegistrationToken::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("A new user registration token was created")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.post", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<SingleResponse<UserRegistrationToken>>), RouteError> {
    // Generate a random token if none was provided
    let token = params.token.unwrap_or_else(|| {
        (&mut rng)
            .sample_iter(&Alphanumeric)
            .take(12)
            .map(char::from)
            .collect()
    });

    let registration_token = repo
        .user_registration_token()
        .add(
            &mut rng,
            &clock,
            token,
            params.usage_limit,
            params.expires_at,
        )
        .await?;

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(registration_token.into())),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "test_token_123",
                "usage_limit": 5,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
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
    async fn test_create_auto_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "usage_limit": 1
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0QMGC989M0XSFVF2X",
            "attributes": {
              "token": "42oTpLoieH5I",
              "usage_limit": 1,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
          }
        }
        "#);
    }
}
