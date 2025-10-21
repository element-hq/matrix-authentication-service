// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use chrono::Duration;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::{BoxRng, TokenType, personal::session::PersonalSessionOwner};
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::error;

use crate::{
    admin::{
        call_context::CallContext,
        model::{InconsistentPersonalSession, PersonalSession},
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

    #[error("User not found")]
    UserNotFound,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session not valid")]
    SessionNotValid,

    #[error("Session does not belong to you")]
    SessionNotYours,
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(InconsistentPersonalSession);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound | Self::SessionNotFound => StatusCode::NOT_FOUND,
            Self::SessionNotValid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::SessionNotYours => StatusCode::FORBIDDEN,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/personal-sessions/{id}/regenerate` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "RegeneratePersonalSessionRequest")]
pub struct Request {
    /// Token expiry time in seconds.
    /// If not set, the token won't expire.
    expires_in: Option<u32>,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("regeneratePersonalSession")
        .summary("Regenerate a personal session by replacing its personal access token")
        .tag("personal-session")
        .response_with::<201, Json<SingleResponse<PersonalSession>>, _>(|t| {
            t.description(
                "Personal session was regenerated and a personal access token was created",
            )
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
        session: caller_session,
        ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    id: UlidPathParam,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<SingleResponse<PersonalSession>>), RouteError> {
    let session_id = *id;

    let session = repo
        .personal_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    if !session.is_valid() {
        // We don't revive revoked sessions through regeneration
        return Err(RouteError::SessionNotValid);
    }

    // If the owner is not the current caller, then currently we reject the
    // regeneration.
    let caller = if let Some(user_id) = caller_session.user_id {
        PersonalSessionOwner::User(user_id)
    } else {
        PersonalSessionOwner::OAuth2Client(caller_session.client_id)
    };
    if session.owner != caller {
        return Err(RouteError::SessionNotYours);
    }

    // Revoke the existing active token for the session.
    let old_token_opt = repo
        .personal_access_token()
        .find_active_for_session(&session)
        .await?;
    let Some(old_token) = old_token_opt else {
        // This shouldn't happen
        error!("session is supposedly valid but had no access token");
        return Err(RouteError::SessionNotValid);
    };

    repo.personal_access_token()
        .revoke(&clock, old_token)
        .await?;

    // Create the regenerated token for the session
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
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use serde_json::{Value, json};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_regenerate_personal_session(pool: PgPool) {
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

        let request = Request::post("/api/admin/v1/personal-sessions")
            .bearer(&token)
            .json(json!({
                "actor_user_id": user.id,
                "human_name": "SuperDuperAdminCLITool Token",
                "scope": "openid urn:mas:admin",
                "expires_in": 3600
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let created: Value = response.json();

        let session_id = created["data"]["id"].as_str().unwrap();

        state.clock.advance(Duration::minutes(3));

        let request = Request::post(format!(
            "/api/admin/v1/personal-sessions/{session_id}/regenerate"
        ))
        .bearer(&token)
        .json(json!({
            "expires_in": 86400
        }));

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
              "human_name": "SuperDuperAdminCLITool Token",
              "scope": "openid urn:mas:admin",
              "last_active_at": null,
              "last_active_ip": null,
              "expires_at": "2022-01-17T14:43:00Z",
              "access_token": "mpt_6cq7FqNSYoosbXl3bbpfh9yNy9NzuR_0vOV2O"
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
}
