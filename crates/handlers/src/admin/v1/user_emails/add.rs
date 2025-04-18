// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::str::FromStr as _;

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{
    BoxRng,
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    user::UserEmailFilter,
};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::UserEmail,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User email {0:?} already in use")]
    EmailAlreadyInUse(String),

    #[error("Email {email:?} is not valid")]
    EmailNotValid {
        email: String,

        #[source]
        source: lettre::address::AddressError,
    },

    #[error("User ID {0} not found")]
    UserNotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::EmailAlreadyInUse(_) => StatusCode::CONFLICT,
            Self::EmailNotValid { .. } => StatusCode::BAD_REQUEST,
            Self::UserNotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/user-emails`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserEmailRequest")]
pub struct Request {
    /// The ID of the user to which the email should be added.
    #[schemars(with = "crate::admin::schema::Ulid")]
    user_id: Ulid,

    /// The email address of the user to add.
    #[schemars(email)]
    email: String,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("addUserEmail")
        .summary("Add a user email")
        .description(r"Add an email address to a user.
Note that this endpoint ignores any policy which would normally prevent the email from being added.")
        .tag("user-email")
        .response_with::<201, Json<SingleResponse<UserEmail>>, _>(|t| {
            let [sample, ..] = UserEmail::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("User email was created").example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::EmailAlreadyInUse(
                "alice@example.com".to_owned(),
            ));
            t.description("Email already in use").example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::EmailNotValid {
                email: "not a valid email".to_owned(),
                source: lettre::address::AddressError::MissingParts,
            });
            t.description("Email is not valid").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserNotFound(Ulid::nil()));
            t.description("User was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_emails.add", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<SingleResponse<UserEmail>>), RouteError> {
    // Find the user
    let user = repo
        .user()
        .lookup(params.user_id)
        .await?
        .ok_or(RouteError::UserNotFound(params.user_id))?;

    // Validate the email
    if let Err(source) = lettre::Address::from_str(&params.email) {
        return Err(RouteError::EmailNotValid {
            email: params.email,
            source,
        });
    }

    // Check if the email already exists
    let count = repo
        .user_email()
        .count(UserEmailFilter::new().for_email(&params.email))
        .await?;

    if count > 0 {
        return Err(RouteError::EmailAlreadyInUse(params.email));
    }

    // Add the email to the user
    let user_email = repo
        .user_email()
        .add(&mut rng, &clock, &user, params.email)
        .await?;

    // Schedule a job to update the user
    repo.queue_job()
        .schedule_job(&mut rng, &clock, ProvisionUserJob::new_for_id(user.id))
        .await?;

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(user_email.into())),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision a user
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "alice@example.com",
                "user_id": alice.id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "user-email",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "email": "alice@example.com"
            },
            "links": {
              "self": "/api/admin/v1/user-emails/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-emails/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "###);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_user_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "alice@example.com",
                "user_id": Ulid::nil(),
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "User ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_email_already_exists(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "alice@example.com",
                "user_id": alice.id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "User email \"alice@example.com\" already in use"
            }
          ]
        }
        "###);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invalid_email(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/user-emails")
            .bearer(&token)
            .json(serde_json::json!({
                "email": "invalid-email",
                "user_id": alice.id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Email \"invalid-email\" is not valid"
            },
            {
              "title": "Missing domain or user"
            }
          ]
        }
        "###);
    }
}
