// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::str::FromStr;

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, extract::State, response::IntoResponse};
use chrono::{DateTime, Utc};
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::record_error;
use mas_data_model::{BoxRng, is_username_template};
use mas_policy::{EvaluationResult, Policy};
use mas_router::UrlBuilder;
use rand::distr::{Alphanumeric, SampleString};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::CallContext,
        model::UserRegistrationToken,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
    room_id::is_valid_room_id,
    username_template,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error("A registration token with the same token already exists")]
    Conflict(Box<mas_data_model::UserRegistrationToken>),

    #[error("Invalid room ID {0:?}")]
    InvalidRoomId(String),

    #[error("Email {email:?} is not valid")]
    EmailNotValid {
        email: String,

        #[source]
        source: lettre::address::AddressError,
    },

    #[error("Username template {template:?} is not valid")]
    InvalidUsernameTemplate {
        template: String,

        #[source]
        source: minijinja::Error,
    },

    #[error("Not allowed by the registration policy: {}", .0.join("; "))]
    NotAllowed(Vec<String>),

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
            Self::Conflict(_) | Self::UsernameTaken(_) => StatusCode::CONFLICT,
            Self::InvalidRoomId(_)
            | Self::EmailNotValid { .. }
            | Self::InvalidUsernameTemplate { .. }
            | Self::NotAllowed(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/user-registration-tokens`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRegistrationTokenRequest")]
pub struct Request {
    /// The token string. If not provided, a random token will be generated.
    token: Option<String>,

    /// Maximum number of times this token can be used. If not provided, the
    /// token can be used an unlimited number of times.
    usage_limit: Option<u32>,

    /// When the token expires. If not provided, the token never expires.
    expires_at: Option<DateTime<Utc>>,

    /// A username to impose on the registering user. If set, the user cannot
    /// choose their own username. A value with `{` is a minijinja template:
    /// registering through the token's `/register?token=…` link renders it
    /// with `random`, 32 random lowercase letters and digits, without showing
    /// the user the name. A template token works only through that link: the
    /// registration token step refuses it. A template must render with a
    /// sample `random`, and the result pass the registration policy. A
    /// username which isn't a template must pass the policy and must not be
    /// taken.
    #[schemars(example = &"user-{{ random }}")]
    username: Option<String>,

    /// An email address to impose on the registering user. If set, the user
    /// cannot choose their own email. It must pass the registration policy.
    email: Option<String>,

    /// Whether registering with this token skips the password step. The user's
    /// identity is then established by verifying their email address, unless
    /// the token has a username template and no email: such an invite link
    /// registers a guest with only a display name.
    #[serde(default)]
    passwordless: bool,

    /// A room to open once the user has registered or signed in through the
    /// token's link, in the client set by `room_invites.client_room_url`.
    /// Without that setting, the link opens no room.
    #[schemars(example = &"!room:example.com")]
    room_id: Option<String>,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("addUserRegistrationToken")
        .summary("Create a new user registration token")
        .tag("user-registration-token")
        .response_with::<201, Json<SingleResponse<UserRegistrationToken>>, _>(|t| {
            let [sample, ..] = UserRegistrationToken::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("A new user registration token was created")
                .example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::InvalidRoomId(
                "#room:example.com".to_owned(),
            ));
            t.description(
                "The room ID, email or username template is not valid, or the registration \
                 policy refuses the email or username",
            )
            .example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response =
                ErrorResponse::from_error(&RouteError::UsernameTaken("alice".to_owned()));
            t.description("A token with the same token already exists, or the username is taken")
                .example(response)
        })
}

/// The violations of a refused policy evaluation, sorted
fn violations(result: EvaluationResult) -> Vec<String> {
    let mut violations: Vec<String> = result
        .violations
        .into_iter()
        .map(|violation| match violation.field {
            Some(field) => format!("{field}: {}", violation.msg),
            None => violation.msg,
        })
        .collect();
    violations.sort();
    violations
}

#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.post", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    State(url_builder): State<UrlBuilder>,
    NoApi(mut rng): NoApi<BoxRng>,
    NoApi(mut policy): NoApi<Policy>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<SingleResponse<UserRegistrationToken>>), RouteError> {
    if let Some(room_id) = params.room_id.as_deref()
        && !is_valid_room_id(room_id)
    {
        return Err(RouteError::InvalidRoomId(room_id.to_owned()));
    }

    if let Some(email) = &params.email
        && let Err(source) = Address::from_str(email)
    {
        return Err(RouteError::EmailNotValid {
            email: email.clone(),
            source,
        });
    }

    // A template is checked by rendering it with a sample, as the name it
    // renders to is only known when registering, which checks it again
    let template_sample = match params.username.as_deref() {
        Some(username) if is_username_template(username) => Some(
            username_template::render_sample(username).map_err(|source| {
                RouteError::InvalidUsernameTemplate {
                    template: username.to_owned(),
                    source,
                }
            })?,
        ),
        _ => None,
    };

    // The same input as `POST /register` in `views/register/password.rs`,
    // which also evaluates a passwordless registration as `Password`. The
    // request comes from an admin client, not the user registering.
    let result = match (
        template_sample.as_deref().or(params.username.as_deref()),
        params.email.as_deref(),
    ) {
        (Some(username), email) => Some(
            policy
                .evaluate_register(mas_policy::RegisterInput {
                    registration_method: mas_policy::RegistrationMethod::Password,
                    username,
                    email,
                    requester: mas_policy::Requester::default(),
                })
                .await?,
        ),
        (None, Some(email)) => Some(
            policy
                .evaluate_email(mas_policy::EmailInput {
                    email,
                    requester: mas_policy::Requester::default(),
                })
                .await?,
        ),
        (None, None) => None,
    };
    if let Some(result) = result
        && !result.valid()
    {
        return Err(RouteError::NotAllowed(violations(result)));
    }

    // The holder of a token pinned to a name someone else already has can
    // never finish registering
    if let Some(username) = &params.username
        && template_sample.is_none()
        && repo.user().exists(username).await?
    {
        return Err(RouteError::UsernameTaken(username.clone()));
    }

    // Generate a random token if none was provided
    let token = params
        .token
        .unwrap_or_else(|| Alphanumeric.sample_string(&mut rng, 12));

    // See if we have an existing token with the same token
    let existing_token = repo.user_registration_token().find_by_token(&token).await?;
    if let Some(existing_token) = existing_token {
        return Err(RouteError::Conflict(Box::new(existing_token)));
    }

    let registration_token = repo
        .user_registration_token()
        .add(
            &mut rng,
            &clock,
            token,
            params.usage_limit,
            params.expires_at,
            params.username,
            params.email,
            params.passwordless,
            params.room_id,
        )
        .await?;

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(UserRegistrationToken::new(
            registration_token,
            clock.now(),
            &url_builder,
        ))),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "test_token_123",
                "usage_limit": 5,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "username": null,
              "email": null,
              "passwordless": false,
              "room_id": null,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_token_123"
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    /// The token travels in the query string of the invite URL, so one with
    /// reserved characters comes back percent-encoded
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_invite_url_encoding(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({ "token": "a token&more" }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["invite_url"],
            "https://example.com/register?token=a+token%26more"
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_auto_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "usage_limit": 1
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0QMGC989M0XSFVF2X",
            "attributes": {
              "token": "42oTpLoieH5I",
              "valid": true,
              "username": null,
              "email": null,
              "passwordless": false,
              "room_id": null,
              "usage_limit": 1,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=42oTpLoieH5I"
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_passwordless(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "invite_alice",
                "username": "alice",
                "email": "alice@example.com",
                "passwordless": true,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "invite_alice",
              "valid": true,
              "username": "alice",
              "email": "alice@example.com",
              "passwordless": true,
              "room_id": null,
              "usage_limit": null,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=invite_alice"
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_room(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut ids = Vec::new();
        for (name, room_id) in [("with_room", Some("!room:example.com")), ("no_room", None)] {
            let request = Request::post("/api/admin/v1/user-registration-tokens")
                .bearer(&token)
                .json(serde_json::json!({ "token": name, "room_id": room_id }));
            let response = state.request(request).await;
            response.assert_status(StatusCode::CREATED);
            let body: serde_json::Value = response.json();
            assert_eq!(
                body["data"]["attributes"]["room_id"],
                serde_json::json!(room_id)
            );
            let id = body["data"]["id"].as_str().unwrap().to_owned();

            let request = Request::get(format!("/api/admin/v1/user-registration-tokens/{id}"))
                .bearer(&token)
                .empty();
            let response = state.request(request).await;
            response.assert_status(StatusCode::OK);
            let body: serde_json::Value = response.json();
            assert_eq!(
                body["data"]["attributes"]["room_id"],
                serde_json::json!(room_id)
            );

            ids.push((id, room_id));
        }

        let request = Request::get("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        for (id, room_id) in ids {
            let listed = body["data"]
                .as_array()
                .unwrap()
                .iter()
                .find(|token| token["id"] == id)
                .unwrap();
            assert_eq!(listed["attributes"]["room_id"], serde_json::json!(room_id));
        }
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_invalid_room(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        for room_id in [
            "#room:example.com",
            "room",
            "!room\u{7}:example.com",
            "!room\u{202E}:example.com",
        ] {
            let request = Request::post("/api/admin/v1/user-registration-tokens")
                .bearer(&token)
                .json(serde_json::json!({ "room_id": room_id }));
            let response = state.request(request).await;
            response.assert_status(StatusCode::BAD_REQUEST);
            let body: serde_json::Value = response.json();
            assert_eq!(
                body["errors"][0]["title"],
                format!("Invalid room ID {room_id:?}")
            );
        }
    }

    /// Post `body` and return the response's status and error titles
    async fn create_errors(
        state: &mut TestState,
        body: serde_json::Value,
    ) -> (StatusCode, Vec<String>) {
        let token = state.token_with_scope("urn:mas:admin").await;
        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(body);
        let response = state.request(request).await;
        let titles = serde_json::from_str::<serde_json::Value>(response.body())
            .ok()
            .and_then(|body| body["errors"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|error| error["title"].as_str().map(ToOwned::to_owned))
            .collect();
        (response.status(), titles)
    }

    /// Post `body` and return the response's status and first error title
    async fn create(state: &mut TestState, body: serde_json::Value) -> (StatusCode, String) {
        let (status, titles) = create_errors(state, body).await;
        (status, titles.into_iter().next().unwrap_or_default())
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_invalid_pins(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

        let (status, title) =
            create(&mut state, serde_json::json!({ "email": "not-an-email" })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(title, r#"Email "not-an-email" is not valid"#);

        // The template's error comes first, then minijinja's render error
        for (username, source) in [
            ("user-{{ random", "syntax error"),
            ("user-{{ email }}", "undefined value"),
        ] {
            let (status, errors) =
                create_errors(&mut state, serde_json::json!({ "username": username })).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{username}");
            assert_eq!(
                errors[0],
                format!("Username template {username:?} is not valid")
            );
            assert!(errors[1].contains(source), "{errors:?}");
        }
    }

    /// A pinned email or username the registration policy refuses is a 400
    /// naming every violation. A template is checked by what it renders to
    /// with a sample.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_refused_by_policy(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/policy-data")
            .bearer(&token)
            .json(serde_json::json!({
                "data": {
                    "banned_domains": ["banned.example"],
                    "registration": {
                        "banned_usernames": { "literals": ["user-banned"], "prefixes": ["banned-"] },
                    },
                },
            }));
        state
            .request(request)
            .await
            .assert_status(StatusCode::CREATED);

        for (body, error) in [
            (
                serde_json::json!({ "email": "bob@banned.example" }),
                "Not allowed by the registration policy: email domain is banned",
            ),
            (
                serde_json::json!({ "email": "bob@banned.example", "username": "user-bob" }),
                "Not allowed by the registration policy: email: email domain is banned",
            ),
            (
                serde_json::json!({ "username": "user-banned" }),
                "Not allowed by the registration policy: username: username is banned",
            ),
            (
                serde_json::json!({ "email": "bob@banned.example", "username": "user-banned" }),
                "Not allowed by the registration policy: email: email domain is banned; username: username is banned",
            ),
            (
                serde_json::json!({ "username": "banned-{{ random }}" }),
                "Not allowed by the registration policy: username: username is banned",
            ),
            (
                serde_json::json!({ "username": "User-{{ random }}" }),
                "Not allowed by the registration policy: username: username contains invalid characters",
            ),
            (
                serde_json::json!({ "username": "user-{random}" }),
                "Not allowed by the registration policy: username: username contains invalid characters",
            ),
        ] {
            let (status, title) = create(&mut state, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
            assert_eq!(title, error);
        }

        let (status, _) = create(
            &mut state,
            serde_json::json!({ "email": "bob@example.com", "username": "user-{{ random }}" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    /// A token pinned to a username nobody can register with is refused. A
    /// template is never taken, even by its sample's name or its own string.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_username_taken(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

        let mut repo = state.repository().await.unwrap();
        for username in [
            "alice",
            "user-a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5",
            "user-{{ random }}",
        ] {
            repo.user()
                .add(&mut state.rng(), &state.clock, username.to_owned())
                .await
                .unwrap();
        }
        repo.save().await.unwrap();

        let (status, title) = create(&mut state, serde_json::json!({ "username": "alice" })).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(title, r#"Username "alice" is already taken"#);

        let (status, _) = create(
            &mut state,
            serde_json::json!({ "token": "template", "username": "user-{{ random }}" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let mut repo = state.repository().await.unwrap();
        let token = repo
            .user_registration_token()
            .find_by_token("template")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token.username.as_deref(), Some("user-{{ random }}"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_conflict(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "test_token_123",
                "usage_limit": 5
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "username": null,
              "email": null,
              "passwordless": false,
              "room_id": null,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_token_123"
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "test_token_123",
                "usage_limit": 5
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
    }
}
