// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, extract::State, response::IntoResponse};
use chrono::{DateTime, Utc};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::BoxRng;
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
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error("A registration token with the same token already exists")]
    Conflict(Box<mas_data_model::UserRegistrationToken>),

    #[error("Invalid room ID {0:?}")]
    InvalidRoomId(String),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::InvalidRoomId(_) => StatusCode::BAD_REQUEST,
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
    /// choose their own username. A value with exactly one `{random}` is a
    /// template: registering through the token's `/register?token=…` link
    /// fills `{random}` in with 32 random lowercase letters and digits,
    /// without showing the user the name.
    username: Option<String>,

    /// An email address to impose on the registering user. If set, the user
    /// cannot choose their own email.
    email: Option<String>,

    /// Whether registering with this token skips the password step. The user's
    /// identity is then established by verifying their email address.
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
            t.description("The room ID is not valid").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.post", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    State(url_builder): State<UrlBuilder>,
    NoApi(mut rng): NoApi<BoxRng>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<SingleResponse<UserRegistrationToken>>), RouteError> {
    if let Some(room_id) = params.room_id.as_deref()
        && !is_valid_room_id(room_id)
    {
        return Err(RouteError::InvalidRoomId(room_id.to_owned()));
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
