// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashSet, str::FromStr};

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, extract::State, response::IntoResponse};
use chrono::Duration;
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::record_error;
use mas_data_model::{BoxRng, SiteConfig};
use mas_policy::Policy;
use mas_storage::queue::{QueueJobRepositoryExt as _, SendGuestInviteEmailJob};
use rand::distributions::{Alphanumeric, DistString};
use ruma_common::UserId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    admin::{call_context::CallContext, response::ErrorResponse},
    impl_from_error_for_route,
    room_id::{is_control_or_bidi, is_valid_room_id},
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
    #[error("Guest invites are disabled")]
    Disabled,

    #[error("Invalid room ID {0:?}")]
    InvalidRoomId(String),

    #[error("No invites given")]
    NoInvites,

    #[error("Email {email:?} is not valid")]
    EmailNotValid {
        email: String,

        #[source]
        source: lettre::address::AddressError,
    },

    #[error("Username {0:?} is given twice")]
    DuplicateUsername(String),

    #[error(
        "Invite for {email:?} with username {username:?} is not allowed: {}",
        .violations.join("; ")
    )]
    NotAllowed {
        email: String,
        username: String,
        violations: Vec<String>,
    },

    #[error("Username {0:?} is already taken")]
    UsernameTaken(String),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::EvaluationError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Disabled => StatusCode::NOT_FOUND,
            Self::InvalidRoomId(_)
            | Self::NoInvites
            | Self::EmailNotValid { .. }
            | Self::DuplicateUsername(_)
            | Self::NotAllowed { .. } => StatusCode::BAD_REQUEST,
            Self::UsernameTaken(_) => StatusCode::CONFLICT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # A guest to invite to the room
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "GuestInvite")]
pub struct Invite {
    /// The address to send the invite to. The guest can only register with
    /// this address.
    #[schemars(email, example = &"alice@example.com")]
    email: String,

    /// The username the guest registers with
    #[schemars(example = &"guest-abcdef")]
    username: String,
}

/// # JSON payload for the `POST /api/admin/v1/invite-guests` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "InviteGuestsRequest")]
pub struct Request {
    /// The room the guests are invited to
    #[schemars(example = &"!room:example.com")]
    room_id: String,

    /// The name of the room, shown in the invite email
    #[schemars(example = &"Project X")]
    room_name: Option<String>,

    /// The Matrix ID of the user sending the invites, shown in the invite
    /// email. It is left out if it isn't a valid Matrix ID.
    #[schemars(example = &"@bob:example.com")]
    inviter: Option<String>,

    /// The display name of the user sending the invites, shown in the invite
    /// email
    #[schemars(example = &"Bob")]
    inviter_name: Option<String>,

    /// The guests to invite. An address given more than once, ignoring case,
    /// is invited once.
    invites: Vec<Invite>,
}

/// # Response to the `POST /api/admin/v1/invite-guests` endpoint
#[derive(Serialize, JsonSchema)]
#[serde(rename = "InviteGuestsResponse")]
pub struct Response {
    /// How many guests were scheduled an invite email, after dropping repeated
    /// addresses
    scheduled: usize,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("inviteGuests")
        .summary("Invite a list of email addresses to a room as guests")
        .description(
            "Mints a single-use, passwordless registration token for each guest, pinned to their \
             address and username, and emails them a link to register with it and open the room. \
             The links are only ever sent to the guests, so they are not in the response.",
        )
        .tag("guest-invite")
        .response_with::<202, Json<Response>, _>(|t| {
            t.description("The invite emails were scheduled")
                .example(Response { scheduled: 2 })
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotAllowed {
                email: "alice@example.com".to_owned(),
                username: "guest-abcdef".to_owned(),
                violations: vec!["email: email domain is banned".to_owned()],
            });
            t.description(
                "The request has an invalid room ID, email or username, no invites, a repeated \
                 username, or an invite the registration policy refuses",
            )
            .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::Disabled);
            t.description("Guest invites are disabled")
                .example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response =
                ErrorResponse::from_error(&RouteError::UsernameTaken("alice".to_owned()));
            t.description("A username is already taken")
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
    name = "handler.admin.v1.guest_invites.post",
    fields(room.id = tracing::field::Empty, recipients.total = params.invites.len()),
    skip_all,
)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    NoApi(mut policy): NoApi<Policy>,
    State(site_config): State<SiteConfig>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<Response>), RouteError> {
    if !site_config.guest_invites_enabled {
        return Err(RouteError::Disabled);
    }

    if !is_valid_room_id(&params.room_id) {
        return Err(RouteError::InvalidRoomId(params.room_id));
    }
    tracing::Span::current().record("room.id", params.room_id.as_str());

    if params.invites.is_empty() {
        return Err(RouteError::NoInvites);
    }

    // Validate everything before minting anything, so that a rejected request
    // sends no email at all
    let mut emails = HashSet::new();
    let mut usernames = HashSet::new();
    let mut valid_invites = Vec::with_capacity(params.invites.len());
    for invite in params.invites {
        if let Err(source) = Address::from_str(&invite.email) {
            return Err(RouteError::EmailNotValid {
                email: invite.email,
                source,
            });
        }

        if !emails.insert(invite.email.to_lowercase()) {
            continue;
        }

        if !usernames.insert(invite.username.clone()) {
            return Err(RouteError::DuplicateUsername(invite.username));
        }

        // The same input as `POST /register` in `views/register/password.rs`,
        // which also evaluates a passwordless registration as `Password`
        let result = policy
            .evaluate_register(mas_policy::RegisterInput {
                registration_method: mas_policy::RegistrationMethod::Password,
                username: &invite.username,
                email: Some(&invite.email),
                // The request comes from the inviter's homeserver, not the guest
                requester: mas_policy::Requester::default(),
            })
            .await?;
        if !result.valid() {
            let mut violations: Vec<String> = result
                .violations
                .into_iter()
                .map(|violation| match violation.field {
                    Some(field) => format!("{field}: {}", violation.msg),
                    None => violation.msg,
                })
                .collect();
            violations.sort();
            return Err(RouteError::NotAllowed {
                email: invite.email,
                username: invite.username,
                violations,
            });
        }

        // A token pins the username, so the recipient of a token pinned to a
        // name someone else already has can never finish registering
        if repo.user().exists(&invite.username).await? {
            return Err(RouteError::UsernameTaken(invite.username));
        }

        valid_invites.push(invite);
    }

    let room_name = params.room_name.as_deref().map(sanitize);
    // The Matrix ID is kept whole or left out, never cut, as a cut ID could
    // show a server the inviter isn't from. The historical grammar is the
    // widest that servers accept, and it has no control or bidi characters.
    let inviter = params.inviter.filter(|inviter| {
        <&UserId>::try_from(inviter.as_str()).is_ok_and(|id| id.validate_historical().is_ok())
    });
    let inviter_name = params.inviter_name.as_deref().map(sanitize);
    let now = clock.now();
    let expires_at = now + site_config.guest_invite_lifetime;
    let scheduled = valid_invites.len();

    for (i, invite) in (0..).zip(valid_invites) {
        let token = Alphanumeric.sample_string(&mut rng, 12);
        let token = repo
            .user_registration_token()
            .add(
                &mut rng,
                &clock,
                token,
                Some(1),
                Some(expires_at),
                Some(invite.username),
                Some(invite.email),
                true,
            )
            .await?;

        repo.queue_job()
            .schedule_job_later(
                &mut rng,
                &clock,
                SendGuestInviteEmailJob::new(
                    token.id,
                    params.room_id.clone(),
                    room_name.clone(),
                    inviter.clone(),
                    inviter_name.clone(),
                ),
                now + SEND_INTERVAL * i,
            )
            .await?;
    }

    repo.save().await?;

    tracing::info!("Scheduled {scheduled} guest invite emails");

    Ok((StatusCode::ACCEPTED, Json(Response { scheduled })))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::{Clock as _, UserRegistrationToken};
    use mas_storage::{
        Pagination,
        queue::{QueueJobRepositoryExt as _, SendGuestInviteEmailJob},
        user::UserRegistrationTokenFilter,
    };
    use sqlx::PgPool;

    use crate::{
        SiteConfig,
        test_utils::{RequestBuilderExt, ResponseExt, TestState, setup, test_site_config},
    };

    async fn tokens(state: &TestState) -> Vec<UserRegistrationToken> {
        let mut repo = state.repository().await.unwrap();
        let page = repo
            .user_registration_token()
            .list(
                UserRegistrationTokenFilter::new(state.clock.now()),
                Pagination::first(100),
            )
            .await
            .unwrap();
        let mut tokens: Vec<_> = page.edges.into_iter().map(|edge| edge.node).collect();
        tokens.sort_by(|a, b| a.email.cmp(&b.email));
        tokens
    }

    async fn job_payloads(pool: &PgPool) -> Vec<serde_json::Value> {
        sqlx::query_scalar(
            "SELECT payload FROM queue_jobs WHERE queue_name = 'send-guest-invite-email'",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn job_statuses(pool: &PgPool) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT status::TEXT FROM queue_jobs
             WHERE queue_name = 'send-guest-invite-email'
             ORDER BY payload->>'room_id'",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// Post `body` and return the response's status and first error title
    async fn invite(state: &mut TestState, body: serde_json::Value) -> (StatusCode, String) {
        let token = state.token_with_scope("urn:mas:admin").await;
        let request = Request::post("/api/admin/v1/invite-guests")
            .bearer(&token)
            .json(body);
        let response = state.request(request).await;
        let title = serde_json::from_str::<serde_json::Value>(response.body())
            .ok()
            .and_then(|body| body["errors"][0]["title"].as_str().map(ToOwned::to_owned))
            .unwrap_or_default();
        (response.status(), title)
    }

    /// Every guest gets a single-use token pinned to their address and
    /// username, expiring after the configured lifetime, and an email job of
    /// their own
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool_with_site_config(
            pool.clone(),
            SiteConfig {
                guest_invite_lifetime: Duration::hours(1),
                ..test_site_config()
            },
        )
        .await
        .unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/invite-guests")
            .bearer(&token)
            .json(serde_json::json!({
                "room_id": "!room:example.com",
                "room_name": "Project X",
                "inviter": "@bob:example.com",
                "inviter_name": "Bob",
                "invites": [
                    { "email": "alice@example.com", "username": "guest-alice" },
                    { "email": "carol@example.com", "username": "guest-carol" },
                ],
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::ACCEPTED);
        assert_eq!(
            response.json::<serde_json::Value>(),
            serde_json::json!({ "scheduled": 2 })
        );

        let tokens = tokens(&state).await;
        let expires_at = state.clock.now() + Duration::hours(1);
        assert_eq!(tokens.len(), 2);
        for (token, name) in tokens.iter().zip(["alice", "carol"]) {
            assert_eq!(token.username.as_deref(), Some(&*format!("guest-{name}")));
            assert_eq!(
                token.email.as_deref(),
                Some(&*format!("{name}@example.com"))
            );
            assert!(token.passwordless);
            assert_eq!(token.usage_limit, Some(1));
            assert_eq!(token.expires_at, Some(expires_at));
        }

        let payloads = job_payloads(&pool).await;
        assert_eq!(payloads.len(), 2);
        for payload in &payloads {
            assert_eq!(payload["room_id"], "!room:example.com");
            assert_eq!(payload["room_name"], "Project X");
            assert_eq!(payload["inviter"], "@bob:example.com");
            assert_eq!(payload["inviter_name"], "Bob");
        }

        // Each job finds its token and renders an email out of it. The sends are
        // spread out, so the second one only comes due later.
        state.run_jobs_in_queue().await;
        state.clock.advance(Duration::seconds(1));
        state.run_jobs_in_queue().await;
        assert_eq!(job_statuses(&pool).await, ["completed", "completed"]);
    }

    /// A version 12 room ID has no server name, and the room name and inviter
    /// are optional
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_v12_room(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();

        let (status, _) = invite(
            &mut state,
            serde_json::json!({
                "room_id": "!31hneApxJ_1o-63DmFrpeqnkFfWppnzWso1JvH3ogLM",
                "invites": [{ "email": "alice@example.com", "username": "guest-alice" }],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let payloads = job_payloads(&pool).await;
        assert_eq!(
            payloads[0]["room_id"],
            "!31hneApxJ_1o-63DmFrpeqnkFfWppnzWso1JvH3ogLM"
        );
        assert_eq!(payloads[0]["room_name"], serde_json::Value::Null);
    }

    /// An address given twice, in any case, is invited once, with the username
    /// it was first given with
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_repeated_email(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/invite-guests")
            .bearer(&token)
            .json(serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [
                    { "email": "Alice@Example.com", "username": "guest-a" },
                    { "email": "alice@example.com", "username": "guest-b" },
                    { "email": "ALICE@EXAMPLE.COM", "username": "guest-a" },
                ],
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::ACCEPTED);
        assert_eq!(
            response.json::<serde_json::Value>(),
            serde_json::json!({ "scheduled": 1 })
        );

        let tokens = tokens(&state).await;
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].username.as_deref(), Some("guest-a"));
        assert_eq!(tokens[0].email.as_deref(), Some("Alice@Example.com"));
    }

    /// A token pinned to a username nobody can register with is refused, rather
    /// than emailed out as a dead link
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_username_taken(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut state.rng(), &state.clock, "guest-alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let (status, title) = invite(
            &mut state,
            serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [
                    { "email": "bob@example.com", "username": "guest-bob" },
                    { "email": "alice@example.com", "username": "guest-alice" },
                ],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(title, r#"Username "guest-alice" is already taken"#);
        assert!(tokens(&state).await.is_empty());
    }

    /// An invite the registration policy refuses is a 400 naming the invite and
    /// every violation, and mints nothing
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_refused_by_policy(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/policy-data")
            .bearer(&token)
            .json(serde_json::json!({
                "data": {
                    "banned_domains": ["banned.example"],
                    "registration": { "banned_usernames": { "literals": ["guest-banned"] } },
                },
            }));
        state
            .request(request)
            .await
            .assert_status(StatusCode::CREATED);

        for (invite, error) in [
            (
                serde_json::json!({ "email": "bob@banned.example", "username": "guest-bob" }),
                r#"Invite for "bob@banned.example" with username "guest-bob" is not allowed: email: email domain is banned"#,
            ),
            (
                serde_json::json!({ "email": "bob@example.com", "username": "guest-banned" }),
                r#"Invite for "bob@example.com" with username "guest-banned" is not allowed: username: username is banned"#,
            ),
            (
                serde_json::json!({ "email": "bob@banned.example", "username": "guest-banned" }),
                r#"Invite for "bob@banned.example" with username "guest-banned" is not allowed: email: email domain is banned; username: username is banned"#,
            ),
        ] {
            let (status, title) = invite_one(&mut state, invite).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(title, error);
        }

        assert!(tokens(&state).await.is_empty());
        assert!(job_payloads(&pool).await.is_empty());
    }

    async fn invite_one(state: &mut TestState, invite: serde_json::Value) -> (StatusCode, String) {
        self::invite(
            state,
            serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [
                    { "email": "alice@example.com", "username": "guest-alice" },
                    invite,
                ],
            }),
        )
        .await
    }

    /// A bad request mints nothing at all, so no part of the batch goes out
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_invalid(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();

        for (body, error) in [
            (
                serde_json::json!({
                    "room_id": "!room:example.com",
                    "invites": [
                        { "email": "alice@example.com", "username": "guest-alice" },
                        { "email": "not-an-email", "username": "guest-bob" },
                    ],
                }),
                r#"Email "not-an-email" is not valid"#,
            ),
            (
                serde_json::json!({
                    "room_id": "#room:example.com",
                    "invites": [{ "email": "alice@example.com", "username": "guest-alice" }],
                }),
                r##"Invalid room ID "#room:example.com""##,
            ),
            (
                serde_json::json!({ "room_id": "!room:example.com", "invites": [] }),
                "No invites given",
            ),
            (
                serde_json::json!({
                    "room_id": "!room:example.com",
                    "invites": [
                        { "email": "alice@example.com", "username": "guest-a" },
                        { "email": "bob@example.com", "username": "guest-a" },
                    ],
                }),
                r#"Username "guest-a" is given twice"#,
            ),
        ] {
            let (status, title) = invite(&mut state, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
            assert_eq!(title, error);
        }

        // A body which doesn't parse, including an invite without a username
        for body in [
            serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [{ "email": "alice@example.com" }],
            }),
            serde_json::json!({ "invites": [] }),
        ] {
            let (status, _) = invite(&mut state, body).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        }

        assert!(tokens(&state).await.is_empty());
        assert!(job_payloads(&pool).await.is_empty());
    }

    /// With guest invites disabled, the endpoint answers as if it didn't exist
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_disabled(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                guest_invites_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let (status, title) = invite(
            &mut state,
            serde_json::json!({
                "room_id": "!room:example.com",
                "invites": [{ "email": "alice@example.com", "username": "guest-alice" }],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(title, "Guest invites are disabled");
    }

    /// The room name and the inviter's name are stripped of control characters
    /// and truncated before they reach the job payload. The inviter's Matrix ID
    /// is kept whole, or left out if it isn't valid.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_names(pool: PgPool) {
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
        for (i, (inviter, expected)) in inviters.into_iter().enumerate() {
            let room_id = format!("!room{i}:example.com");
            let (status, _) = invite(
                &mut state,
                serde_json::json!({
                    "room_id": room_id,
                    "room_name": format!("{controls}Project{controls} X{}", "x".repeat(64 * 1024)),
                    "inviter": inviter,
                    "inviter_name": format!("B\u{202E}ob{}", "é".repeat(200)),
                    "invites": [{ "email": "alice@example.com", "username": "guest-alice" }],
                }),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED);

            let payloads = job_payloads(&pool).await;
            let payload = payloads
                .iter()
                .find(|payload| payload["room_id"] == room_id)
                .unwrap();
            assert_eq!(payload["room_name"], format!("Project X{}", "x".repeat(91)));
            assert_eq!(payload["inviter"], expected, "{inviter:?}");
            assert_eq!(payload["inviter_name"], format!("Bob{}", "é".repeat(97)));
        }
    }

    /// A token revoked by the time its job runs gets no email. The tokens pin
    /// an address that doesn't parse, so a send fails the job.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite_revoked_before_sending(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        for (room_id, revoke) in [("!a:example.com", true), ("!b:example.com", false)] {
            let token = repo
                .user_registration_token()
                .add(
                    &mut rng,
                    &state.clock,
                    room_id.to_owned(),
                    Some(1),
                    None,
                    Some("guest-alice".to_owned()),
                    Some("not-an-email".to_owned()),
                    true,
                )
                .await
                .unwrap();
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
                    SendGuestInviteEmailJob::new(token.id, room_id.to_owned(), None, None, None),
                )
                .await
                .unwrap();
        }
        repo.save().await.unwrap();

        state.run_jobs_in_queue().await;
        assert_eq!(job_statuses(&pool).await, ["completed", "failed"]);
    }
}
