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
use mas_data_model::BoxRng;
use mas_policy::{EvaluationResult, Policy};
use mas_router::UrlBuilder;
use mas_storage::user::UserRegistrationTokenParams;
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
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error("A registration token with the same token already exists")]
    Conflict(Box<mas_data_model::UserRegistrationToken>),

    #[error("Email {email:?} is not valid")]
    EmailNotValid {
        email: String,

        #[source]
        source: lettre::address::AddressError,
    },

    #[error(transparent)]
    NotAllowed(#[from] NotAllowed),

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
            Self::EmailNotValid { .. } | Self::NotAllowed(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Not allowed by the registration policy: {}", .0.join("; "))]
pub struct NotAllowed(Vec<String>);

impl NotAllowed {
    /// An error naming `violations`, sorted, if there are any
    pub(super) fn check(mut violations: Vec<String>) -> Result<(), Self> {
        if violations.is_empty() {
            return Ok(());
        }
        violations.sort();
        Err(Self(violations))
    }
}

/// # JSON payload for the `POST /api/admin/v1/user-registration-tokens`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRegistrationTokenRequest")]
pub struct Request {
    /// The token string. If not provided, a random token will be generated.
    /// Anyone holding the token can open its invite URL, which shows the
    /// username and email address it imposes, so a token provided here must be
    /// as hard to guess as a generated one.
    token: Option<String>,

    /// Maximum number of times this token can be used. If not provided, the
    /// token can be used an unlimited number of times.
    usage_limit: Option<u32>,

    /// When the token expires. If not provided, the token never expires.
    expires_at: Option<DateTime<Utc>>,

    /// A username to impose on the registering user. If set, the user cannot
    /// choose their own username. It must pass the registration policy and
    /// must not be taken.
    username: Option<String>,

    /// An email address to impose on the registering user. If set, the user
    /// cannot choose their own email. It must pass the registration policy.
    email: Option<String>,

    /// Whether registering with this token skips the password step. The user's
    /// identity is then established by verifying their email address.
    #[serde(default)]
    passwordless: bool,
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
            let response = ErrorResponse::from_error(&RouteError::NotAllowed(NotAllowed(vec![
                "username: username is banned".to_owned(),
            ])));
            t.description(
                "The email is not valid, or the registration policy refuses the email or the \
                 username",
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

/// The violations of a refused policy evaluation
fn violations(result: EvaluationResult) -> Vec<String> {
    result
        .violations
        .into_iter()
        .map(|violation| match violation.field {
            Some(field) => format!("{field}: {}", violation.msg),
            None => violation.msg,
        })
        .collect()
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
    if let Some(email) = &params.email
        && let Err(source) = Address::from_str(email)
    {
        return Err(RouteError::EmailNotValid {
            email: email.clone(),
            source,
        });
    }

    // The same input as `POST /register` in `views/register/password.rs`,
    // which also evaluates a passwordless registration as `Password`. The
    // request comes from an admin client, not the user registering.
    let result = match (params.username.as_deref(), params.email.as_deref()) {
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
    NotAllowed::check(result.map(violations).unwrap_or_default())?;

    // The holder of a token pinned to a name someone else already has can
    // never finish registering. An email address already in use is not
    // refused: a client minting tokens for addresses its users typed would
    // tell them which addresses have an account
    if let Some(username) = &params.username
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
            UserRegistrationTokenParams {
                token,
                usage_limit: params.usage_limit,
                expires_at: params.expires_at,
                username: params.username,
                email: params.email,
                passwordless: params.passwordless,
            },
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
    }

    /// A pinned email or username the registration policy refuses is a 400
    /// naming every violation
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
        ] {
            let (status, title) = create(&mut state, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
            assert_eq!(title, error);
        }

        let (status, _) = create(
            &mut state,
            serde_json::json!({ "email": "bob@example.com", "username": "user-bob" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    /// A token pinned to a username nobody can register with is refused
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_username_taken(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let (status, title) = create(&mut state, serde_json::json!({ "username": "alice" })).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(title, r#"Username "alice" is already taken"#);
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
