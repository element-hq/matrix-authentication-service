// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::BoxRng;
use mas_storage::queue::{QueueJobRepositoryExt as _, SyncDevicesJob};
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{OAuth2Session, Resource},
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

    #[error("OAuth 2.0 session with ID {0} not found")]
    NotFound(Ulid),

    #[error("OAuth 2.0 session with ID {0} is already finished")]
    AlreadyFinished(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::AlreadyFinished(_) => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("finishOAuth2Session")
        .summary("Finish an OAuth 2.0 session")
        .description(
            "Calling this endpoint will finish the OAuth 2.0 session, preventing any further use. If the session has a user associated with it, a job will be scheduled to sync the user's devices with the homeserver.",
        )
        .tag("oauth2-session")
        .response_with::<200, Json<SingleResponse<OAuth2Session>>, _>(|t| {
            // Get the finished session sample
            let [_, _, finished_session] = OAuth2Session::samples();
            let id = finished_session.id();
            let response = SingleResponse::new(
                finished_session,
                format!("/api/admin/v1/oauth2-sessions/{id}/finish"),
            );
            t.description("OAuth 2.0 session was finished").example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::AlreadyFinished(Ulid::nil()));
            t.description("Session is already finished")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("OAuth 2.0 session was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.oauth2_sessions.finish", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<OAuth2Session>>, RouteError> {
    let id = *id;
    let session = repo
        .oauth2_session()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    // Check if the session is already finished
    if session.finished_at().is_some() {
        return Err(RouteError::AlreadyFinished(id));
    }

    // If the session has a user associated with it, schedule a job to sync devices
    if let Some(user_id) = session.user_id {
        tracing::info!(user.id = %user_id, "Scheduling device sync job for user");
        let job = SyncDevicesJob::new_for_id(user_id);
        repo.queue_job().schedule_job(&mut rng, &clock, job).await?;
    }

    // Finish the session
    let session = repo.oauth2_session().finish(&clock, session).await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        OAuth2Session::from(session),
        format!("/api/admin/v1/oauth2-sessions/{id}/finish"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::{AccessToken, Clock as _};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_finish_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Get the session ID from the token we just created
        let mut repo = state.repository().await.unwrap();
        let AccessToken { session_id, .. } = repo
            .oauth2_access_token()
            .find_by_token(&token)
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post(format!("/api/admin/v1/oauth2-sessions/{session_id}/finish"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The finished_at timestamp should be the same as the current time
        assert_eq!(
            body["data"]["attributes"]["finished_at"],
            serde_json::json!(state.clock.now())
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_finish_already_finished_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

        // Create first admin token for the API call
        let admin_token = state.token_with_scope("urn:mas:admin").await;

        // Create a second admin session that we'll finish
        let second_admin_token = state.token_with_scope("urn:mas:admin").await;

        // Get the second session and finish it first
        let mut repo = state.repository().await.unwrap();
        let AccessToken { session_id, .. } = repo
            .oauth2_access_token()
            .find_by_token(&second_admin_token)
            .await
            .unwrap()
            .unwrap();

        let session = repo
            .oauth2_session()
            .lookup(session_id)
            .await
            .unwrap()
            .unwrap();

        // Finish the session first
        let session = repo
            .oauth2_session()
            .finish(&state.clock, session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Move the clock forward
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/api/admin/v1/oauth2-sessions/{}/finish",
            session.id
        ))
        .bearer(&admin_token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!(
                "OAuth 2.0 session with ID {} is already finished",
                session.id
            )
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_finish_unknown_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request =
            Request::post("/api/admin/v1/oauth2-sessions/01040G2081040G2081040G2081/finish")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "OAuth 2.0 session with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
