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
use ulid::Ulid;
use tracing::{error, info};

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
            t.description("All sessions was killed").example(response)
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
    let _affected = repo.compat_session().finish_bulk(&clock, filter).await?;

    match _affected {
        0 => info!("No active compatibility sessions to end"),
        1 => info!("Ended 1 active compatibility session"),
        _ => info!("Ended {_affected} active compatibility sessions"),
    }

    let filter = OAuth2SessionFilter::new().for_user(&user).active_only();
    let _affected = repo.oauth2_session().finish_bulk(&clock, filter).await?;

    match _affected {
        0 => info!("No active compatibility sessions to end"),
        1 => info!("Ended 1 active OAuth 2.0 session"),
        _ => info!("Ended {_affected} active OAuth 2.0 sessions"),
    }

    let filter = BrowserSessionFilter::new().for_user(&user).active_only();
    let _affected = repo.browser_session().finish_bulk(&clock, filter).await?;

    match _affected {
        0 => info!("No active browser sessions to end"),
        1 => info!("Ended 1 active browser session"),
        _ => info!("Ended {_affected} active browser sessions"),
    }

    // // Schedule a job to sync the devices of the user with the homeserver
    // warn!("Scheduling job to sync devices for the user");
    repo.queue_job()
        .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
        .await?;

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        User::from(user),
        format!("/api/admin/v1/users/{id}/kill-sessions"),
    )))
}

// #[cfg(test)]
// mod tests {
//     use chrono::Duration;
//     use hyper::{Request, StatusCode};
//     use mas_data_model::{Clock as _, Device};
//     use sqlx::PgPool;

//     use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState,
// setup};

//     #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
//     async fn test_finish_session(pool: PgPool) {
//         setup();
//         let mut state = TestState::from_pool(pool).await.unwrap();
//         let token = state.token_with_scope("urn:mas:admin").await;
//         let mut rng = state.rng();

//         // Provision a user and a compat session
//         let mut repo = state.repository().await.unwrap();
//         let user = repo
//             .user()
//             .add(&mut rng, &state.clock, "alice".to_owned())
//             .await
//             .unwrap();
//         let device = Device::generate(&mut rng);
//         let session = repo
//             .compat_session()
//             .add(&mut rng, &state.clock, &user, device, None, false, None)
//             .await
//             .unwrap();
//         repo.save().await.unwrap();

//         let request = Request::post(format!(
//             "/api/admin/v1/misc/kill-sessions/{}/finish",
//             session.id
//         ))
//         .bearer(&token)
//         .empty();
//         let response = state.request(request).await;
//         response.assert_status(StatusCode::OK);
//         let body: serde_json::Value = response.json();

//         // The finished_at timestamp should be the same as the current time
//         assert_eq!(
//             body["data"]["attributes"]["finished_at"],
//             serde_json::json!(state.clock.now())
//         );
//     }

//     #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
//     async fn test_finish_already_finished_session(pool: PgPool) {
//         setup();
//         let mut state = TestState::from_pool(pool).await.unwrap();
//         let token = state.token_with_scope("urn:mas:admin").await;
//         let mut rng = state.rng();

//         // Provision a user and a compat session
//         let mut repo = state.repository().await.unwrap();
//         let user = repo
//             .user()
//             .add(&mut rng, &state.clock, "alice".to_owned())
//             .await
//             .unwrap();
//         let device = Device::generate(&mut rng);
//         let session = repo
//             .compat_session()
//             .add(&mut rng, &state.clock, &user, device, None, false, None)
//             .await
//             .unwrap();

//         // Finish the session first
//         let session = repo
//             .compat_session()
//             .finish(&state.clock, session)
//             .await
//             .unwrap();

//         repo.save().await.unwrap();

//         // Move the clock forward
//         state.clock.advance(Duration::try_minutes(1).unwrap());

//         let request = Request::post(format!(
//             "/api/admin/v1/misc/kill-sessions/{}/finish",
//             session.id
//         ))
//         .bearer(&token)
//         .empty();
//         let response = state.request(request).await;
//         response.assert_status(StatusCode::BAD_REQUEST);
//         let body: serde_json::Value = response.json();
//         assert_eq!(
//             body["errors"][0]["title"],
//             format!(
//                 "Compatibility session with ID {} is already finished",
//                 session.id
//             )
//         );
//     }

//     #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
//     async fn test_finish_unknown_session(pool: PgPool) {
//         setup();
//         let mut state = TestState::from_pool(pool).await.unwrap();
//         let token = state.token_with_scope("urn:mas:admin").await;

//         let request =
//
// Request::post("/api/admin/v1/misc/kill-sessions/01040G2081040G2081040G2081/
// finish")                 .bearer(&token)
//                 .empty();
//         let response = state.request(request).await;
//         response.assert_status(StatusCode::NOT_FOUND);
//         let body: serde_json::Value = response.json();
//         assert_eq!(
//             body["errors"][0]["title"],
//             "Compatibility session with ID 01040G2081040G2081040G2081 not
// found"         );
//     }
// }
