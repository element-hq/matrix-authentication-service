// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use aide::{NoApi, OperationIo, transform::TransformOperation};
use anyhow::Context;
use axum::{Json, extract::State, response::IntoResponse};
use chrono::Duration;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::{BoxRng, Device, TokenType};
use mas_matrix::HomeserverConnection;
use oauth2_types::scope::Scope;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{InconsistentPersonalSession, PersonalSession},
        response::{ErrorResponse, SingleResponse},
        v1::personal_sessions::personal_session_owner_from_caller,
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User not found")]
    UserNotFound,

    #[error("User is not active")]
    UserDeactivated,

    #[error("Invalid scope")]
    InvalidScope,
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(InconsistentPersonalSession);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound => StatusCode::NOT_FOUND,
            Self::UserDeactivated => StatusCode::GONE,
            Self::InvalidScope => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/personal-sessions` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "CreatePersonalSessionRequest")]
pub struct Request {
    /// The user this session will act on behalf of
    #[schemars(with = "crate::admin::schema::Ulid")]
    actor_user_id: Ulid,

    /// Human-readable name for the session
    human_name: String,

    /// `OAuth2` scopes for this session
    scope: String,

    /// Token expiry time in seconds.
    /// If not set, the token won't expire.
    expires_in: Option<u32>,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("createPersonalSession")
        .summary("Create a new personal session with personal access token")
        .tag("personal-session")
        .response_with::<201, Json<SingleResponse<PersonalSession>>, _>(|t| {
            t.description("Personal session and personal access token were created")
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::InvalidScope);
            t.description("Invalid scope provided").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserNotFound);
            t.description("User was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.personal_sessions.add", skip_all)]
pub async fn handler(
    CallContext {
        mut repo,
        clock,
        session,
        ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    NoApi(State(homeserver)): NoApi<State<Arc<dyn HomeserverConnection>>>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<SingleResponse<PersonalSession>>), RouteError> {
    let owner = personal_session_owner_from_caller(&session);

    let actor_user = repo
        .user()
        .lookup(params.actor_user_id)
        .await?
        .ok_or(RouteError::UserNotFound)?;

    if !actor_user.is_valid_actor() {
        return Err(RouteError::UserDeactivated);
    }

    let scope: Scope = params.scope.parse().map_err(|_| RouteError::InvalidScope)?;

    // Create the personal session
    let session = repo
        .personal_session()
        .add(
            &mut rng,
            &clock,
            owner,
            &actor_user,
            params.human_name,
            scope,
        )
        .await?;

    // Create the initial token for the session
    let access_token_string = TokenType::PersonalAccessToken.generate(&mut rng);
    let access_token = repo
        .personal_access_token()
        .add(
            &mut rng,
            &clock,
            &session,
            &access_token_string,
            params
                .expires_in
                .map(|exp_in| Duration::seconds(i64::from(exp_in))),
        )
        .await?;

    // If the session has a device, we should add those to the homeserver now
    if session.has_device() {
        // Lock the user sync to make sure we don't get into a race condition
        repo.user().acquire_lock_for_sync(&actor_user).await?;

        for scope in &*session.scope {
            if let Some(device) = Device::from_scope_token(scope) {
                // NOTE: We haven't relinquished the repo at this point,
                // so we are holding a transaction across the homeserver
                // operation.
                // This is suboptimal, but simpler.
                // Given this is an administrative endpoint, this is a tolerable
                // compromise for now.
                homeserver
                    .upsert_device(&actor_user.username, device.as_str(), None)
                    .await
                    .context("Failed to provision device")
                    .map_err(|e| RouteError::Internal(e.into()))?;
            }
        }
    }

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(
            PersonalSession::try_from((session, Some(access_token)))?
                .with_token(access_token_string),
        )),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use serde_json::Value;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_personal_session_with_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Create a user for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request_body = serde_json::json!({
            "actor_user_id": user.id,
            "human_name": "Test Session",
            "scope": "openid urn:mas:admin",
            "expires_in": 3600
        });

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(&request_body);

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "personal-session",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "revoked_at": null,
              "owner_user_id": null,
              "owner_client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
              "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_name": "Test Session",
              "scope": "openid urn:mas:admin",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": "2022-01-16T15:40:00Z",
              "access_token": "mpt_FM44zJN5qePGMLvvMXC4Ds1A3lCWc6_bJ9Wj1"
            },
            "links": {
              "self": "/api/admin/v1/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/api/admin/v1/personal-sessions/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_personal_session_invalid_user(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request_body = serde_json::json!({
            "actor_user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "scope": "openid",
            "human_name": "Test Session",
            "expires_in": 3600
        });

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(&request_body);

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_personal_session_invalid_scope(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Create a user for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request_body = serde_json::json!({
            "actor_user_id": user.id,
            "human_name": "Test Session",
            "scope": "invalid\nscope",
            "expires_in": 3600
        });

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(&request_body);

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
