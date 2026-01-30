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
        model::{CompatSession, Resource},
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

    #[error("Compatibility session with ID {0} not found")]
    NotFound(Ulid),

    #[error("Compatibility session with ID {0} is already finished")]
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
        .id("finishCompatSession")
        .summary("Finish a compatibility session")
        .description(
            "Calling this endpoint will finish the compatibility session, preventing any further use. A job will be scheduled to sync the user's devices with the homeserver.",
        )
        .tag("compat-session")
        .response_with::<200, Json<SingleResponse<CompatSession>>, _>(|t| {
            // Get the finished session sample
            let [_, finished_session, _] = CompatSession::samples();
            let id = finished_session.id();
            let response = SingleResponse::new(
                finished_session,
                format!("/api/admin/v1/compat-sessions/{id}/finish"),
            );
            t.description("Compatibility session was finished").example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::AlreadyFinished(Ulid::nil()));
            t.description("Session is already finished")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("Compatibility session was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.compat_sessions.finish", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<CompatSession>>, RouteError> {
    let id = *id;
    let session = repo
        .compat_session()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    // Check if the session is already finished
    if session.finished_at().is_some() {
        return Err(RouteError::AlreadyFinished(id));
    }

    // Schedule a job to sync the devices of the user with the homeserver
    tracing::info!(user.id = %session.user_id, "Scheduling device sync job for user");
    repo.queue_job()
        .schedule_job(
            &mut rng,
            &clock,
            SyncDevicesJob::new_for_id(session.user_id),
        )
        .await?;

    // Finish the session
    let session = repo.compat_session().finish(&clock, session).await?;

    // Get the SSO login info for the response
    let sso_login = repo.compat_sso_login().find_for_session(&session).await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        CompatSession::from((session, sso_login)),
        format!("/api/admin/v1/compat-sessions/{id}/finish"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::{Clock as _, Device};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_finish_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision a user and a compat session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(&mut rng, &state.clock, &user, device, None, false, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post(format!(
            "/api/admin/v1/compat-sessions/{}/finish",
            session.id
        ))
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
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision a user and a compat session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(&mut rng, &state.clock, &user, device, None, false, None)
            .await
            .unwrap();

        // Finish the session first
        let session = repo
            .compat_session()
            .finish(&state.clock, session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Move the clock forward
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/api/admin/v1/compat-sessions/{}/finish",
            session.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!(
                "Compatibility session with ID {} is already finished",
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
            Request::post("/api/admin/v1/compat-sessions/01040G2081040G2081040G2081/finish")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Compatibility session with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
