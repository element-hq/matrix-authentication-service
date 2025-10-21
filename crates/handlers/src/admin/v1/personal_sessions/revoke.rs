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

    #[error("Personal session with ID {0} not found")]
    NotFound(Ulid),

    #[error("Personal session with ID {0} is already revoked")]
    AlreadyRevoked(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(InconsistentPersonalSession);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::AlreadyRevoked(_) => StatusCode::CONFLICT,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("revokePersonalSession")
        .summary("Revoke a personal session")
        .tag("personal-session")
        .response_with::<200, Json<SingleResponse<PersonalSession>>, _>(|t| {
            let [sample, ..] = PersonalSession::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("Personal session was revoked")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("Personal session not found")
                .example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::AlreadyRevoked(Ulid::nil()));
            t.description("Personal session already revoked")
                .example(response)
        })
}

#[tracing::instrument(
    name = "handler.admin.v1.personal_sessions.revoke",
    skip_all,
    fields(personal_session.id = %*session_id),
)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    session_id: UlidPathParam,
) -> Result<Json<SingleResponse<PersonalSession>>, RouteError> {
    let session_id = *session_id;
    let session = repo
        .personal_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::NotFound(session_id))?;

    if session.is_revoked() {
        return Err(RouteError::AlreadyRevoked(session_id));
    }

    let session = repo.personal_session().revoke(&clock, session).await?;

    if session.has_device() {
        // If the session has a device, then we are now
        // deleting a device and should schedule a device sync to clean up.
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SyncDevicesJob::new_for_id(session.actor_user_id),
            )
            .await?;
    }

    repo.save().await?;

    Ok(Json(SingleResponse::new_canonical(
        PersonalSession::try_from((session, None))?,
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::{Clock, personal::session::PersonalSessionOwner};
    use oauth2_types::scope::Scope;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_revoke_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Create a user and personal session for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let personal_session = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([]),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post(format!(
            "/api/admin/v1/personal-sessions/{}/revoke",
            personal_session.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // The revoked_at timestamp should be the same as the current time
        assert_eq!(
            body["data"]["attributes"]["revoked_at"],
            serde_json::json!(Clock::now(&state.clock))
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_revoke_already_revoked_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Create a user and personal session for testing
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let personal_session = repo
            .personal_session()
            .add(
                &mut rng,
                &state.clock,
                PersonalSessionOwner::from(&user),
                &user,
                "Test session".to_owned(),
                Scope::from_iter([]),
            )
            .await
            .unwrap();

        // Revoke the session first
        let session = repo
            .personal_session()
            .revoke(&state.clock, personal_session)
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Move the clock forward
        state.clock.advance(Duration::try_minutes(1).unwrap());

        let request = Request::post(format!(
            "/api/admin/v1/personal-sessions/{}/revoke",
            session.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            format!("Personal session with ID {} is already revoked", session.id)
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_revoke_unknown_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request =
            Request::post("/api/admin/v1/personal-sessions/01040G2081040G2081040G2081/revoke")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["errors"][0]["title"],
            "Personal session with ID 01040G2081040G2081040G2081 not found"
        );
    }
}
