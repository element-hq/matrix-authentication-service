// Copyright 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, extract::State, response::IntoResponse};
use chrono::{DateTime, Utc};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_policy::PolicyFactory;
use mas_router::UrlBuilder;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};
use ulid::Ulid;

use super::add::{AllowedEmailsError, NotAllowed, allowed_emails_violations, parse_allowed_emails};
use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, UserRegistrationToken},
        params::UlidPathParam,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

// Any value that is present is considered Some value, including null.
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

/// # JSON payload for the `PUT /api/admin/v1/user-registration-tokens/{id}` endpoint
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "EditUserRegistrationTokenRequest")]
pub struct Request {
    /// New expiration date for the token, or null to remove expiration
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_some"
    )]
    #[expect(clippy::option_option)]
    expires_at: Option<Option<DateTime<Utc>>>,

    /// New usage limit for the token, or null to remove the limit
    #[expect(clippy::option_option)]
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_some"
    )]
    usage_limit: Option<Option<u32>>,

    /// New email addresses the registering user must use one of, replacing
    /// the old ones, or null to allow any. It can't be set on a token with an
    /// `email` or without `passwordless`. It must not be empty, and each
    /// address must pass the registration policy. Repeats of an address in
    /// another case are dropped.
    #[expect(clippy::option_option)]
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "deserialize_some"
    )]
    #[schemars(example = &["alice@example.com", "bob@example.com"])]
    allowed_emails: Option<Option<Vec<String>>>,
}

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Registration token with ID {0} not found")]
    NotFound(Ulid),

    #[error("The token has an `email`, so it can't have `allowed_emails`")]
    EmailAndAllowedEmails,

    #[error("The token isn't `passwordless`, so it can't have `allowed_emails`")]
    AllowedEmailsNotPasswordless,

    #[error(transparent)]
    InvalidAllowedEmails(#[from] AllowedEmailsError),

    #[error(transparent)]
    NotAllowed(#[from] NotAllowed),
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::InstantiateError);
impl_from_error_for_route!(mas_policy::EvaluationError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::EmailAndAllowedEmails
            | Self::AllowedEmailsNotPasswordless
            | Self::InvalidAllowedEmails(_)
            | Self::NotAllowed(_) => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("updateUserRegistrationToken")
        .summary("Update a user registration token")
        .description("Update properties of a user registration token such as expiration and usage limit. To set a field to null (removing the limit/expiration), include the field with a null value. To leave a field unchanged, omit it from the request body.")
        .tag("user-registration-token")
        .response_with::<200, Json<SingleResponse<UserRegistrationToken>>, _>(|t| {
            // Get the valid token sample
            let [valid_token, _] = UserRegistrationToken::samples();
            let id = valid_token.id();
            let response = SingleResponse::new(valid_token, format!("/api/admin/v1/user-registration-tokens/{id}"));
            t.description("Registration token was updated").example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::EmailAndAllowedEmails);
            t.description(
                "`allowed_emails` is empty or set on a token with an `email` or without \
                 `passwordless`, or an address in it is not valid or refused by the registration \
                 policy",
            )
            .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("Registration token was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.update", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    State(url_builder): State<UrlBuilder>,
    State(policy_factory): State<Arc<PolicyFactory>>,
    id: UlidPathParam,
    Json(request): Json<Request>,
) -> Result<Json<SingleResponse<UserRegistrationToken>>, RouteError> {
    let id = *id;

    // Get the token
    let mut token = repo
        .user_registration_token()
        .lookup(id)
        .await?
        .ok_or(RouteError::NotFound(id))?;

    let allowed_emails = match request.allowed_emails {
        None => None,
        Some(None) => Some(None),
        Some(Some(_)) if token.email.is_some() => return Err(RouteError::EmailAndAllowedEmails),
        Some(Some(_)) if !token.passwordless => {
            return Err(RouteError::AllowedEmailsNotPasswordless);
        }
        Some(Some(emails)) => {
            let emails = parse_allowed_emails(emails)?;
            let mut policy = policy_factory.instantiate().await?;
            NotAllowed::check(allowed_emails_violations(&mut policy, &emails).await?)?;
            Some(Some(emails))
        }
    };

    // Update expiration if present in the request
    if let Some(expires_at) = request.expires_at {
        token = repo
            .user_registration_token()
            .set_expiry(token, expires_at)
            .await?;
    }

    // Update usage limit if present in the request
    if let Some(usage_limit) = request.usage_limit {
        token = repo
            .user_registration_token()
            .set_usage_limit(token, usage_limit)
            .await?;
    }

    if let Some(allowed_emails) = allowed_emails {
        token = repo
            .user_registration_token()
            .set_allowed_emails(token, allowed_emails)
            .await?;
    }

    repo.save().await?;

    Ok(Json(SingleResponse::new(
        UserRegistrationToken::new(token, clock.now(), &url_builder),
        format!("/api/admin/v1/user-registration-tokens/{id}"),
    )))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::Clock as _;
    use mas_storage::user::UserRegistrationTokenParams;
    use serde_json::json;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_update_expiry(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();

        // Create a token without expiry
        let registration_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                UserRegistrationTokenParams {
                    token: "test_update_expiry".to_owned(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Update with an expiry date
        let future_date = state.clock.now() + Duration::days(30);
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": future_date
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Verify expiry was updated
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_expiry",
              "valid": true,
              "username": null,
              "email": null,
              "allowed_emails": null,
              "passwordless": false,
              "continue_url": null,
              "usage_limit": null,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": "2022-02-15T14:40:00Z",
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_update_expiry"
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

        // Now remove the expiry
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": null
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Verify expiry was removed
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_expiry",
              "valid": true,
              "username": null,
              "email": null,
              "allowed_emails": null,
              "passwordless": false,
              "continue_url": null,
              "usage_limit": null,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_update_expiry"
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
    async fn test_update_usage_limit(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();

        // Create a token with usage limit
        let registration_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                UserRegistrationTokenParams {
                    token: "test_update_limit".to_owned(),
                    usage_limit: Some(5),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Update the usage limit
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "usage_limit": 10
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Verify usage limit was updated
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_limit",
              "valid": true,
              "username": null,
              "email": null,
              "allowed_emails": null,
              "passwordless": false,
              "continue_url": null,
              "usage_limit": 10,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_update_limit"
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

        // Now remove the usage limit
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "usage_limit": null
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Verify usage limit was removed
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_limit",
              "valid": true,
              "username": null,
              "email": null,
              "allowed_emails": null,
              "passwordless": false,
              "continue_url": null,
              "usage_limit": null,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_update_limit"
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
    async fn test_update_multiple_fields(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();

        // Create a token
        let registration_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                UserRegistrationTokenParams {
                    token: "test_update_multiple".to_owned(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Update both fields
        let future_date = state.clock.now() + Duration::days(30);
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({
            "expires_at": future_date,
            "usage_limit": 20
        }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // Both fields were updated
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_multiple",
              "valid": true,
              "username": null,
              "email": null,
              "allowed_emails": null,
              "passwordless": false,
              "continue_url": null,
              "usage_limit": 20,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": "2022-02-15T14:40:00Z",
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_update_multiple"
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
    async fn test_update_no_fields(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut repo = state.repository().await.unwrap();

        // Create a token
        let registration_token = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                UserRegistrationTokenParams {
                    token: "test_update_none".to_owned(),
                    usage_limit: Some(5),
                    expires_at: Some(state.clock.now() + Duration::days(30)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Send empty update
        let request = Request::put(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            registration_token.id
        ))
        .bearer(&token)
        .json(json!({}));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        // It shouldn't have updated the token
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_update_none",
              "valid": true,
              "username": null,
              "email": null,
              "allowed_emails": null,
              "passwordless": false,
              "continue_url": null,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": "2022-02-15T14:40:00Z",
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_update_none"
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
    async fn test_update_unknown_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Try to update a non-existent token
        let request =
            Request::put("/api/admin/v1/user-registration-tokens/01040G2081040G2081040G2081")
                .bearer(&token)
                .json(json!({
                    "usage_limit": 5
                }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["errors"][0]["title"],
            "Registration token with ID 01040G2081040G2081040G2081 not found"
        );
    }

    /// Put `body` to the token `id`, and return the response's status and
    /// body
    async fn put(
        state: &mut TestState,
        id: ulid::Ulid,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let token = state.token_with_scope("urn:mas:admin").await;
        let request = Request::put(format!("/api/admin/v1/user-registration-tokens/{id}"))
            .bearer(&token)
            .json(body);
        let response = state.request(request).await;
        (response.status(), response.json())
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_update_allowed_emails(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

        let mut repo = state.repository().await.unwrap();
        let listed = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                UserRegistrationTokenParams {
                    token: "test_update_allowed_emails".to_owned(),
                    username: Some("user-{{ random }}".to_owned()),
                    allowed_emails: Some(vec!["alice@example.com".to_owned()]),
                    passwordless: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let pinned = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                UserRegistrationTokenParams {
                    token: "test_update_pinned_email".to_owned(),
                    email: Some("alice@example.com".to_owned()),
                    passwordless: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let open = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                UserRegistrationTokenParams {
                    token: "test_update_open".to_owned(),
                    passwordless: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let with_password = repo
            .user_registration_token()
            .add(
                &mut state.rng(),
                &state.clock,
                UserRegistrationTokenParams {
                    token: "test_update_with_password".to_owned(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        // A token without a list can be given one
        let (status, body) = put(
            &mut state,
            open.id,
            json!({ "allowed_emails": ["alice@example.com"] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["data"]["attributes"]["allowed_emails"],
            json!(["alice@example.com"])
        );

        // A new list replaces the old one, without the repeats in another case
        let (status, body) = put(
            &mut state,
            listed.id,
            json!({ "allowed_emails": ["Bob@Example.com", "carol@example.com", "bob@example.com"] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["data"]["attributes"]["allowed_emails"],
            json!(["Bob@Example.com", "carol@example.com"])
        );

        // Omitted, the list is unchanged
        let (status, body) = put(&mut state, listed.id, json!({ "usage_limit": 5 })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["data"]["attributes"]["allowed_emails"],
            json!(["Bob@Example.com", "carol@example.com"])
        );

        let request = Request::post("/api/admin/v1/policy-data")
            .bearer(&state.token_with_scope("urn:mas:admin").await)
            .json(json!({ "data": { "banned_domains": ["banned.example"] } }));
        state
            .request(request)
            .await
            .assert_status(StatusCode::CREATED);

        for (id, body, error) in [
            (
                pinned.id,
                json!({ "allowed_emails": ["alice@example.com"] }),
                "The token has an `email`, so it can't have `allowed_emails`",
            ),
            (
                with_password.id,
                json!({ "allowed_emails": ["alice@example.com"] }),
                "The token isn't `passwordless`, so it can't have `allowed_emails`",
            ),
            (
                listed.id,
                json!({ "allowed_emails": [] }),
                "`allowed_emails` must not be empty",
            ),
            (
                listed.id,
                json!({ "allowed_emails": ["not-an-email"] }),
                r#"Email "not-an-email" is not valid"#,
            ),
            (
                listed.id,
                json!({ "allowed_emails": ["alice@example.com", "bob@banned.example"] }),
                "Not allowed by the registration policy: bob@banned.example: email domain is banned",
            ),
        ] {
            let (status, body) = put(&mut state, id, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
            assert_eq!(body["errors"][0]["title"], error);
        }

        // A refused update changes nothing
        let mut repo = state.repository().await.unwrap();
        let token = repo
            .user_registration_token()
            .lookup(listed.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            token.allowed_emails,
            Some(vec![
                "Bob@Example.com".to_owned(),
                "carol@example.com".to_owned()
            ])
        );

        // Null allows any address
        let (status, body) = put(&mut state, listed.id, json!({ "allowed_emails": null })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["attributes"]["allowed_emails"], json!(null));
    }
}
