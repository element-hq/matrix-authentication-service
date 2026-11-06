// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashSet, str::FromStr};

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use chrono::Duration;
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::record_error;
use mas_data_model::BoxRng;
use mas_storage::queue::{QueueJobRepositoryExt as _, SendInviteEmailJob};
use ruma_common::UserId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    admin::{call_context::CallContext, response::ErrorResponse},
    impl_from_error_for_route,
    room_id::is_control_or_bidi,
};

/// How many characters of the room name and of the inviter's name are kept.
/// Both can be up to 64 KiB, and this keeps the job payload and the email small
/// and readable. The value itself is a choice.
const MAX_NAME_LENGTH: usize = 100;

/// The delay between the scheduled sends of one request, so that a large batch
/// doesn't burst against the SMTP server
const SEND_INTERVAL: Duration = Duration::milliseconds(100);

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error("No invites given")]
    NoInvites,

    #[error("Registration token ID {0} not found")]
    TokenNotFound(Ulid),

    #[error("Registration token {0} is not valid")]
    TokenNotValid(Ulid),

    #[error("Registration token {0} has no email address, so the invite needs one")]
    NoEmail(Ulid),

    #[error("Email {email:?} is not the one registration token {id} is for")]
    EmailMismatch { id: Ulid, email: String },

    #[error("Email {email:?} is not valid")]
    EmailNotValid {
        email: String,

        #[source]
        source: lettre::address::AddressError,
    },

    #[error("Registration token {0} has no room, so the request can't name one")]
    RoomNameWithoutRoom(Ulid),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::TokenNotFound(_) => StatusCode::NOT_FOUND,
            Self::NoInvites
            | Self::TokenNotValid(_)
            | Self::NoEmail(_)
            | Self::EmailMismatch { .. }
            | Self::EmailNotValid { .. }
            | Self::RoomNameWithoutRoom(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # A registration token to email a link for
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "InviteEmail")]
pub struct Invite {
    /// The ID of the registration token
    #[schemars(with = "crate::admin::schema::Ulid")]
    registration_token_id: Ulid,

    /// The address to send the link to. Required if the token has no email
    /// address, and otherwise the token's address, ignoring case.
    #[schemars(email, example = &"alice@example.com")]
    email: Option<String>,
}

/// # JSON payload for the `POST /api/admin/v1/user-registration-tokens/invite-emails` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "InviteEmailsRequest")]
pub struct Request {
    /// The tokens to email a link for. A token and address given more than
    /// once, ignoring case, are emailed once.
    invites: Vec<Invite>,

    /// The name of the room the tokens open, shown in the email. Only allowed
    /// if every token opens a room.
    #[schemars(example = &"Project X")]
    room_name: Option<String>,

    /// The Matrix ID of the user sending the invites, shown in the email. It is
    /// left out if it isn't a valid Matrix ID.
    #[schemars(example = &"@bob:example.com")]
    inviter: Option<String>,

    /// The display name of the user sending the invites, shown in the email
    #[schemars(example = &"Bob")]
    inviter_name: Option<String>,
}

/// # Response to the `POST /api/admin/v1/user-registration-tokens/invite-emails` endpoint
#[derive(Serialize, JsonSchema)]
#[serde(rename = "InviteEmailsResponse")]
pub struct Response {
    /// How many emails were scheduled, after dropping repeated invites
    scheduled: usize,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("sendUserRegistrationTokenInviteEmails")
        .summary("Email invite links for user registration tokens")
        .description(
            "Emails each address a link to register with its token, which also opens the \
             token's room, if it has one. The email is sent only if the token is still valid \
             by then.",
        )
        .tag("user-registration-token")
        .response_with::<202, Json<Response>, _>(|t| {
            t.description("The emails were scheduled")
                .example(Response { scheduled: 2 })
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NoEmail(Ulid::nil()));
            t.description(
                "The request has no invites, an invalid token, or an address which is missing, \
                 invalid or not the token's, or names a room for a token without one",
            )
            .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::TokenNotFound(Ulid::nil()));
            t.description("A registration token was not found")
                .example(response)
        })
}

/// Strip control and bidirectional characters, and keep at most
/// [`MAX_NAME_LENGTH`] characters
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|c| !is_control_or_bidi(*c))
        .take(MAX_NAME_LENGTH)
        .collect()
}

#[tracing::instrument(
    name = "handler.admin.v1.user_registration_tokens.invite_emails",
    fields(recipients.total = params.invites.len()),
    skip_all,
)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<Response>), RouteError> {
    if params.invites.is_empty() {
        return Err(RouteError::NoInvites);
    }

    let now = clock.now();

    // Check everything before scheduling anything, so that a rejected request
    // sends no email at all
    let mut seen = HashSet::new();
    let mut sends = Vec::with_capacity(params.invites.len());
    for invite in params.invites {
        let id = invite.registration_token_id;
        let token = repo
            .user_registration_token()
            .lookup(id)
            .await?
            .ok_or(RouteError::TokenNotFound(id))?;

        if !token.is_valid(now) {
            return Err(RouteError::TokenNotValid(id));
        }

        if params.room_name.is_some() && token.room_id.is_none() {
            return Err(RouteError::RoomNameWithoutRoom(id));
        }

        let email = match (invite.email, token.email) {
            (Some(email), Some(pinned)) if !email.eq_ignore_ascii_case(&pinned) => {
                return Err(RouteError::EmailMismatch { id, email });
            }
            (_, Some(pinned)) => pinned,
            (Some(email), None) => email,
            (None, None) => return Err(RouteError::NoEmail(id)),
        };
        if let Err(source) = Address::from_str(&email) {
            return Err(RouteError::EmailNotValid { email, source });
        }

        if seen.insert((id, email.to_lowercase())) {
            sends.push((id, email));
        }
    }

    let room_name = params.room_name.as_deref().map(sanitize);
    // The Matrix ID is kept whole or left out, never cut, as a cut ID could
    // show a server the inviter isn't from. The historical grammar is the
    // widest that servers accept, and it has no control or bidi characters.
    let inviter = params.inviter.filter(|inviter| {
        <&UserId>::try_from(inviter.as_str()).is_ok_and(|id| id.validate_historical().is_ok())
    });
    let inviter_name = params.inviter_name.as_deref().map(sanitize);
    let scheduled = sends.len();

    for (i, (id, email)) in (0..).zip(sends) {
        repo.queue_job()
            .schedule_job_later(
                &mut rng,
                &clock,
                SendInviteEmailJob::new(
                    id,
                    email,
                    room_name.clone(),
                    inviter.clone(),
                    inviter_name.clone(),
                ),
                now + SEND_INTERVAL * i,
            )
            .await?;
    }

    repo.save().await?;

    tracing::info!("Scheduled {scheduled} invite emails");

    Ok((StatusCode::ACCEPTED, Json(Response { scheduled })))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::UserRegistrationToken;
    use mas_storage::queue::{QueueJobRepositoryExt as _, SendInviteEmailJob};
    use rand::distr::{Alphanumeric, SampleString};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, TestState, setup};

    /// Add a token with this email and room
    async fn add_token(
        state: &TestState,
        email: Option<&str>,
        room_id: Option<&str>,
    ) -> UserRegistrationToken {
        let mut repo = state.repository().await.unwrap();
        let token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                Alphanumeric.sample_string(&mut state.rng(), 12),
                None,
                None,
                None,
                email.map(ToOwned::to_owned),
                false,
                room_id.map(ToOwned::to_owned),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        token
    }

    async fn job_payloads(pool: &PgPool) -> Vec<serde_json::Value> {
        sqlx::query_scalar(
            "SELECT payload FROM queue_jobs WHERE queue_name = 'send-invite-email'
             ORDER BY payload->>'email'",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// The invite email jobs' statuses, ordered by their tokens' IDs
    async fn job_statuses(pool: &PgPool) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT status::TEXT FROM queue_jobs
             WHERE queue_name = 'send-invite-email'
             ORDER BY payload->>'registration_token_id'",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// Post `body` and return the response's status and body
    async fn send(
        state: &mut TestState,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let token = state.token_with_scope("urn:mas:admin").await;
        let request = Request::post("/api/admin/v1/user-registration-tokens/invite-emails")
            .bearer(&token)
            .json(body);
        let response = state.request(request).await;
        let body = serde_json::from_str(response.body()).unwrap_or_default();
        (response.status(), body)
    }

    /// Each token's email goes to its address, with the room and the inviter
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_send(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let alice = add_token(&state, Some("alice@example.com"), Some("!room:example.com")).await;
        let carol = add_token(&state, Some("carol@example.com"), Some("!room:example.com")).await;

        let (status, body) = send(
            &mut state,
            serde_json::json!({
                "invites": [
                    { "registration_token_id": alice.id },
                    { "registration_token_id": carol.id },
                ],
                "room_name": "Project X",
                "inviter": "@bob:example.com",
                "inviter_name": "Bob",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body, serde_json::json!({ "scheduled": 2 }));

        let payloads = job_payloads(&pool).await;
        assert_eq!(payloads.len(), 2);
        for (payload, (token, email)) in payloads
            .iter()
            .zip([(&alice, "alice@example.com"), (&carol, "carol@example.com")])
        {
            assert_eq!(payload["registration_token_id"], token.id.to_string());
            assert_eq!(payload["email"], email);
            assert_eq!(payload["room_name"], "Project X");
            assert_eq!(payload["inviter"], "@bob:example.com");
            assert_eq!(payload["inviter_name"], "Bob");
        }

        // Each job renders an email out of its token. The sends are spread out,
        // so the second one only comes due later.
        state.run_jobs_in_queue().await;
        state.clock.advance(Duration::seconds(1));
        state.run_jobs_in_queue().await;
        assert_eq!(job_statuses(&pool).await, ["completed", "completed"]);
    }

    /// A token without an email address goes to the addresses given, each once
    /// ignoring case, and a token without a room can be sent
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_send_unpinned(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = add_token(&state, None, None).await;

        let (status, body) = send(
            &mut state,
            serde_json::json!({
                "invites": [
                    { "registration_token_id": token.id, "email": "Alice@Example.com" },
                    { "registration_token_id": token.id, "email": "bob@example.com" },
                    { "registration_token_id": token.id, "email": "ALICE@EXAMPLE.COM" },
                ],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body, serde_json::json!({ "scheduled": 2 }));

        let emails: Vec<_> = job_payloads(&pool)
            .await
            .into_iter()
            .map(|payload| payload["email"].clone())
            .collect();
        assert_eq!(emails, ["Alice@Example.com", "bob@example.com"]);

        state.run_jobs_in_queue().await;
        state.clock.advance(Duration::seconds(1));
        state.run_jobs_in_queue().await;
        assert_eq!(job_statuses(&pool).await, ["completed", "completed"]);
    }

    /// A token's email address can be given, in any case, and is sent to as
    /// the token has it
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_send_pinned_email_given(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = add_token(&state, Some("alice@example.com"), None).await;

        let (status, body) = send(
            &mut state,
            serde_json::json!({
                "invites": [
                    { "registration_token_id": token.id, "email": "ALICE@example.com" },
                    { "registration_token_id": token.id },
                ],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body, serde_json::json!({ "scheduled": 1 }));
        assert_eq!(job_payloads(&pool).await[0]["email"], "alice@example.com");
    }

    /// A bad request schedules nothing at all, so no part of the batch goes out
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_send_invalid(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let valid = add_token(&state, Some("alice@example.com"), Some("!room:example.com")).await;
        let unpinned = add_token(&state, None, Some("!room:example.com")).await;
        let no_room = add_token(&state, Some("bob@example.com"), None).await;
        let revoked = add_token(&state, Some("carol@example.com"), None).await;
        let mut repo = state.repository().await.unwrap();
        repo.user_registration_token()
            .revoke(&state.clock, revoked.clone())
            .await
            .unwrap();
        repo.save().await.unwrap();
        let unknown = ulid::Ulid::nil();

        for (invite, room_name, status, error) in [
            (
                serde_json::json!({ "registration_token_id": unknown }),
                None,
                StatusCode::NOT_FOUND,
                format!("Registration token ID {unknown} not found"),
            ),
            (
                serde_json::json!({ "registration_token_id": revoked.id }),
                None,
                StatusCode::BAD_REQUEST,
                format!("Registration token {} is not valid", revoked.id),
            ),
            (
                serde_json::json!({ "registration_token_id": unpinned.id }),
                None,
                StatusCode::BAD_REQUEST,
                format!(
                    "Registration token {} has no email address, so the invite needs one",
                    unpinned.id
                ),
            ),
            (
                serde_json::json!({ "registration_token_id": unpinned.id, "email": "not-an-email" }),
                None,
                StatusCode::BAD_REQUEST,
                r#"Email "not-an-email" is not valid"#.to_owned(),
            ),
            (
                serde_json::json!({ "registration_token_id": valid.id, "email": "bob@example.com" }),
                None,
                StatusCode::BAD_REQUEST,
                format!(
                    r#"Email "bob@example.com" is not the one registration token {} is for"#,
                    valid.id
                ),
            ),
            (
                serde_json::json!({ "registration_token_id": no_room.id }),
                Some("Project X"),
                StatusCode::BAD_REQUEST,
                format!(
                    "Registration token {} has no room, so the request can't name one",
                    no_room.id
                ),
            ),
        ] {
            let (actual_status, body) = send(
                &mut state,
                serde_json::json!({
                    "invites": [{ "registration_token_id": valid.id }, invite],
                    "room_name": room_name,
                }),
            )
            .await;
            assert_eq!(actual_status, status, "{error}");
            assert_eq!(body["errors"][0]["title"], error);
        }

        let (status, body) = send(&mut state, serde_json::json!({ "invites": [] })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["errors"][0]["title"], "No invites given");

        let (status, _) = send(
            &mut state,
            serde_json::json!({ "invites": [{ "email": "alice@example.com" }] }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        assert!(job_payloads(&pool).await.is_empty());
    }

    /// The room name and the inviter's name are stripped of control characters
    /// and truncated before they reach the job payload. The inviter's Matrix ID
    /// is kept whole, or left out if it isn't valid.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_send_names(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();

        let controls = "\u{0}\n\u{7f}\u{85}\u{202A}\u{202E}\u{2066}\u{2069}";
        let long_id = format!("@{}:example.com", "b".repeat(200));
        let inviters = [
            (long_id.clone(), serde_json::Value::from(long_id)),
            (
                format!("@bob{controls}:example.com"),
                serde_json::Value::Null,
            ),
        ];
        for (inviter, expected) in inviters {
            let token =
                add_token(&state, Some("alice@example.com"), Some("!room:example.com")).await;
            let (status, _) = send(
                &mut state,
                serde_json::json!({
                    "invites": [{ "registration_token_id": token.id }],
                    "room_name": format!("{controls}Project{controls} X{}", "x".repeat(64 * 1024)),
                    "inviter": inviter,
                    "inviter_name": format!("B\u{202E}ob{}", "é".repeat(200)),
                }),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED);

            let payloads = job_payloads(&pool).await;
            let payload = payloads
                .iter()
                .find(|payload| payload["registration_token_id"] == token.id.to_string())
                .unwrap();
            assert_eq!(payload["room_name"], format!("Project X{}", "x".repeat(91)));
            assert_eq!(payload["inviter"], expected, "{inviter:?}");
            assert_eq!(payload["inviter_name"], format!("Bob{}", "é".repeat(97)));
        }
    }

    /// A token revoked by the time its job runs gets no email. The jobs carry
    /// an address that doesn't parse, so a send fails the job.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_send_revoked_before_sending(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();

        let mut expected = Vec::new();
        for revoke in [true, false] {
            let token = add_token(&state, None, None).await;
            let mut repo = state.repository().await.unwrap();
            if revoke {
                repo.user_registration_token()
                    .revoke(&state.clock, token.clone())
                    .await
                    .unwrap();
            }
            repo.queue_job()
                .schedule_job(
                    &mut rng,
                    &state.clock,
                    SendInviteEmailJob::new(token.id, "not-an-email".to_owned(), None, None, None),
                )
                .await
                .unwrap();
            repo.save().await.unwrap();
            expected.push((token.id, if revoke { "completed" } else { "failed" }));
        }

        state.run_jobs_in_queue().await;
        expected.sort_unstable();
        let expected: Vec<_> = expected.into_iter().map(|(_, status)| status).collect();
        assert_eq!(job_statuses(&pool).await, expected);
    }
}
