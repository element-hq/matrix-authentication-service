// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::BoxRng;
use mas_storage::{
    compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter,
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    user::BrowserSessionFilter,
};
use tracing::error;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, User},
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

    #[error("User ID {0} not found")]
    NotFound(Ulid),

    #[error("User ID {0} has no session to kill")]
    NoSession(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NoSession(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("KillSessions")
        .summary("Kill all sessions (compatibility, oauth2, user sessions)")
        .description(
            "Calling this endpoint will end all the compatibility, oauth2 and user sessions, preventing any further use. A job will be scheduled to sync the user's devices with the homeserver.",
        )
        .tag("user")
        .response_with::<200, Json<SingleResponse<User>>, _>(|t| {
            // In the samples, the second user is the one which can request admin
            let [_alice, bob, ..] = User::samples();
            let id = bob.id();
            let response = SingleResponse::new(bob, format!("/api/admin/v1/users/{id}/kill-sessions"));
            t.description("All sessions were killed").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NoSession(Ulid::nil()));
            t.description("User has no active sessions")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.kill_sessions", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<User>>, RouteError> {
    let id = *id;
    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    let filter = CompatSessionFilter::new().for_user(&user).active_only();
    let compat_session_affected = repo.compat_session().finish_bulk(&clock, filter).await?;

    let filter = OAuth2SessionFilter::new().for_user(&user).active_only();
    let oauth2_session_affected = repo.oauth2_session().finish_bulk(&clock, filter).await?;

    let filter = BrowserSessionFilter::new().for_user(&user).active_only();
    let browser_session_affected = repo.browser_session().finish_bulk(&clock, filter).await?;

    if compat_session_affected + oauth2_session_affected + browser_session_affected == 0 {
        return Err(RouteError::NoSession(user.id));
    }

    // Schedule a job to sync the devices of the user with the homeserver
    repo.queue_job()
        .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
        .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/kill-sessions"),
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
    async fn test_kill_sessions(pool: PgPool) {
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

        let request = Request::post(format!("/api/admin/v1/users/{}/kill-sessions", &user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["data"]["id"], format!("{}", &user.id));
        // The finished_at timestamp should be the same as the current time
        let mut repo = state.repository().await.unwrap();
        let expected = repo
            .compat_session()
            .lookup(session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expected.finished_at().unwrap(), state.clock.now());
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_kill_already_finished_session(pool: PgPool) {
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

        let request = Request::post(format!("/api/admin/v1/users/{}/kill-sessions", &user.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["errors"][0]["title"],
            format!("User ID {} has no session to kill", &user.id)
        );
        let mut repo = state.repository().await.unwrap();
        let expected = repo
            .compat_session()
            .lookup(session.id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(expected.finished_at().unwrap(), state.clock.now());
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_kill_sessions_on_unknown_users(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/users/01040G2081040G2081040G2081/kill-sessions")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        //         let body: serde_json::Value = response.json();
        //         assert_eq!(
        //             body["errors"][0]["title"],
        //             "Compatibility session with ID 01040G2081040G2081040G2081
        // not found"         );
    }
}
