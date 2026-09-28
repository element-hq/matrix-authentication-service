// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashSet, str::FromStr};

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::record_error;
use mas_data_model::BoxRng;
use mas_storage::room_invite::{RoomInvite, schedule_room_invites};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    admin::{call_context::CallContext, response::ErrorResponse},
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error("Invalid email address {0:?}")]
    InvalidEmail(String),

    #[error("Username {0:?} is given twice")]
    DuplicateUsername(String),

    #[error("Username {0:?} is already taken")]
    UsernameTaken(String),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::InvalidEmail(_) | Self::DuplicateUsername(_) => StatusCode::BAD_REQUEST,
            Self::UsernameTaken(_) => StatusCode::CONFLICT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # A person to invite to the room
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "RoomInvite")]
pub struct Invite {
    /// The address to send the invite to. The recipient can only register with
    /// this address.
    #[schemars(example = &"alice@example.com")]
    email: String,

    /// A username to impose on the recipient. If not set, they choose their
    /// own.
    #[schemars(example = &"guest-abcdef")]
    username: Option<String>,
}

/// # JSON payload for the `POST /api/admin/v1/room-invites` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddRoomInvitesRequest")]
pub struct Request {
    /// The room the recipients are invited to
    #[schemars(example = &"!room:example.com")]
    room_id: String,

    /// The people to invite. An address given more than once is invited once.
    invites: Vec<Invite>,
}

/// # Response to the `POST /api/admin/v1/room-invites` endpoint
#[derive(Serialize, JsonSchema)]
#[serde(rename = "AddRoomInvitesResponse")]
pub struct Response {
    /// How many recipients were scheduled an invite email, after dropping
    /// repeated addresses
    scheduled: usize,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("addRoomInvites")
        .summary("Invite a list of email addresses to a room")
        .description(
            "Mints a single-use, passwordless registration token for each recipient and emails \
             them a link to register with it. The links are only ever sent to the recipients, so \
             they are not in the response.",
        )
        .tag("room-invite")
        .response_with::<202, Json<Response>, _>(|t| {
            t.description("The invite emails were scheduled")
                .example(Response { scheduled: 2 })
        })
        .response_with::<400, RouteError, _>(|t| {
            let response =
                ErrorResponse::from_error(&RouteError::InvalidEmail("not-an-email".to_owned()));
            t.description("The request has an invalid email or a repeated username")
                .example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UsernameTaken("alice".to_owned()));
            t.description("A username is already taken").example(response)
        })
}

#[tracing::instrument(
    name = "handler.admin.v1.room_invites.post",
    fields(room.id = params.room_id, recipients.total = params.invites.len()),
    skip_all,
)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<Response>), RouteError> {
    // Validate everything before minting anything, so that a rejected request
    // sends no email at all
    let mut usernames = HashSet::new();
    let mut invites = Vec::with_capacity(params.invites.len());
    for invite in params.invites {
        if Address::from_str(&invite.email).is_err() {
            return Err(RouteError::InvalidEmail(invite.email));
        }

        if let Some(username) = &invite.username {
            if !usernames.insert(username.clone()) {
                return Err(RouteError::DuplicateUsername(username.clone()));
            }

            // A token pins the username, so the recipient of a token pinned to
            // a name someone else already has can never finish registering
            if repo.user().exists(username).await? {
                return Err(RouteError::UsernameTaken(username.clone()));
            }
        }

        invites.push(RoomInvite {
            email: invite.email,
            username: invite.username,
        });
    }

    let scheduled =
        schedule_room_invites(&mut repo, &mut rng, &clock, &params.room_id, invites).await?;
    repo.save().await?;

    tracing::info!("Scheduled {scheduled} room invite emails");

    Ok((StatusCode::ACCEPTED, Json(Response { scheduled })))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    /// Every recipient gets a single-use token pinned to their address, and an
    /// email job of their own
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/room-invites")
            .bearer(&token)
            .json(serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [
                    { "email": "alice@example.com", "username": "guest-alice" },
                    { "email": "bob@example.com" },
                ],
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::ACCEPTED);

        let tokens: Vec<(String, Option<String>, Option<String>, bool, Option<i32>)> =
            sqlx::query_as(
                "SELECT token, username, email, passwordless, usage_limit
                 FROM user_registration_tokens ORDER BY email",
            )
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(
            (
                tokens[0].1.as_deref(),
                tokens[0].2.as_deref(),
                tokens[0].3,
                tokens[0].4
            ),
            (Some("guest-alice"), Some("alice@example.com"), true, Some(1))
        );
        // Without a username the recipient picks their own
        assert_eq!(
            (tokens[1].1.as_deref(), tokens[1].2.as_deref()),
            (None, Some("bob@example.com"))
        );

        let jobs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM queue_jobs WHERE queue_name = 'send-room-invite-email'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(jobs, 2);

        // Each job finds its token and renders an email out of it. The sends are
        // spread out, so the second one only comes due later.
        state.run_jobs_in_queue().await;
        state.clock.advance(Duration::seconds(1));
        state.run_jobs_in_queue().await;

        let completed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM queue_jobs
             WHERE queue_name = 'send-room-invite-email' AND status = 'completed'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(completed, 2);
    }

    /// An address given twice is invited once
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_repeated_email(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/room-invites")
            .bearer(&token)
            .json(serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [
                    { "email": "alice@example.com" },
                    { "email": "alice@example.com" },
                ],
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::ACCEPTED);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_registration_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    /// A token pinned to a username nobody can register with is refused, rather
    /// than emailed out as a dead link
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_username_taken(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let admin_token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/room-invites")
            .bearer(&admin_token)
            .json(serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [{ "email": "alice@example.com", "username": "alice" }],
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
    }

    /// A bad request mints nothing at all, so no part of the batch goes out
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_invalid(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/room-invites")
            .bearer(&token)
            .json(serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [
                    { "email": "alice@example.com" },
                    { "email": "not-an-email" },
                ],
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let request = Request::post("/api/admin/v1/room-invites")
            .bearer(&token)
            .json(serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [
                    { "email": "alice@example.com", "username": "guest-a" },
                    { "email": "bob@example.com", "username": "guest-a" },
                ],
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_registration_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
