// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::num::NonZeroU64;

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::BoxRng;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::UserSessionLimitOverride,
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
    UserNotFound(Ulid),

    #[error("OAuth 2.0 client ID {0} not found")]
    ClientNotFound(Ulid),

    #[error("A session limit override already exists for this user and client")]
    AlreadyExists,

    #[error("hard_limit must be greater than or equal to soft_limit")]
    InvalidLimits,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound(_) | Self::ClientNotFound(_) => StatusCode::NOT_FOUND,
            Self::AlreadyExists => StatusCode::CONFLICT,
            Self::InvalidLimits => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/user-session-limit-overrides`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserSessionLimitOverrideRequest")]
pub struct Request {
    /// The ID of the user this override applies to
    #[schemars(with = "crate::admin::schema::Ulid")]
    user_id: Ulid,

    /// The OAuth 2.0 client this override applies to.
    /// Omit or set to `null` for a global override.
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    #[serde(default)]
    client_id: Option<Ulid>,

    /// Soft session limit
    soft_limit: NonZeroU64,

    /// Hard session limit
    hard_limit: NonZeroU64,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("addUserSessionLimitOverride")
        .summary("Create a user session limit override")
        .description(
            "Create a per-user override of session limit soft/hard numbers. \
             `client_id` may be omitted for a global override. \
             `max_session_threshold` and `dangerous_hard_limit_eviction` are not \
             overridable here; they continue to come from the YAML configuration.",
        )
        .tag("user-session-limit-override")
        .response_with::<201, Json<SingleResponse<UserSessionLimitOverride>>, _>(|t| {
            let [sample, ..] = UserSessionLimitOverride::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("User session limit override was created")
                .example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::InvalidLimits);
            t.description("Limits are invalid").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserNotFound(Ulid::nil()));
            t.description("User or OAuth 2.0 client was not found")
                .example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::AlreadyExists);
            t.description("An override already exists for this user and client")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_session_limit_overrides.add", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<SingleResponse<UserSessionLimitOverride>>), RouteError> {
    if params.hard_limit < params.soft_limit {
        return Err(RouteError::InvalidLimits);
    }

    let user = repo
        .user()
        .lookup(params.user_id)
        .await?
        .ok_or(RouteError::UserNotFound(params.user_id))?;

    if let Some(client_id) = params.client_id
        && repo.oauth2_client().lookup(client_id).await?.is_none()
    {
        return Err(RouteError::ClientNotFound(client_id));
    }

    if repo
        .user_session_limit_override()
        .find(&user, params.client_id)
        .await?
        .is_some()
    {
        return Err(RouteError::AlreadyExists);
    }

    let override_row = repo
        .user_session_limit_override()
        .add(
            &mut rng,
            &clock,
            &user,
            params.client_id,
            params.soft_limit,
            params.hard_limit,
        )
        .await?;

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(override_row.into())),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use oauth2_types::requests::GrantType;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_global(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-session-limit-overrides")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "soft_limit": 3,
                "hard_limit": 5,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-session-limit-override",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "updated_at": "2022-01-16T14:40:00Z",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "client_id": null,
              "soft_limit": 3,
              "hard_limit": 5
            },
            "links": {
              "self": "/api/admin/v1/user-session-limit-overrides/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-session-limit-overrides/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_for_client(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &state.clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-session-limit-overrides")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "client_id": client.id,
                "soft_limit": 2,
                "hard_limit": 4,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["data"]["attributes"]["client_id"],
            client.id.to_string()
        );
        assert_eq!(body["data"]["attributes"]["soft_limit"], 2);
        assert_eq!(body["data"]["attributes"]["hard_limit"], 4);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_user_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-session-limit-overrides")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": Ulid::nil(),
                "soft_limit": 3,
                "hard_limit": 5,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_client_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-session-limit-overrides")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "client_id": Ulid::nil(),
                "soft_limit": 3,
                "hard_limit": 5,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_already_exists(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-session-limit-overrides")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "soft_limit": 3,
                "hard_limit": 5,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let request = Request::post("/api/admin/v1/user-session-limit-overrides")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "soft_limit": 4,
                "hard_limit": 6,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invalid_limits(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-session-limit-overrides")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "soft_limit": 5,
                "hard_limit": 3,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
