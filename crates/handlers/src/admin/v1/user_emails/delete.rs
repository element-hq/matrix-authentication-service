// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::BoxRng;
use mas_storage::queue::{ProvisionUserJob, QueueJobRepositoryExt as _};
use ulid::Ulid;

use crate::{
    admin::{call_context::CallContext, params::UlidPathParam, response::ErrorResponse},
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User email ID {0} not found")]
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
        .id("deleteUserEmail")
        .summary("Delete a user email")
        .tag("user-email")
        .response_with::<204, (), _>(|t| t.description("User email was found"))
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User email was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.user_emails.delete", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    id: UlidPathParam,
) -> Result<StatusCode, RouteError> {
    let email = repo
        .user_email()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    let job = ProvisionUserJob::new_for_id(email.user_id);
    repo.user_email().remove(email).await?;

    // Schedule a job to update the user
    repo.queue_job().schedule_job(&mut rng, &clock, job).await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_delete(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision a user and an email
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let mas_data_model::UserEmail { id, .. } = repo
            .user_email()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                "alice@example.com".to_owned(),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::delete(format!("/api/admin/v1/user-emails/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Verify that the email was deleted
        let request = Request::get(format!("/api/admin/v1/user-emails/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let email_id = Ulid::nil();
        let request = Request::delete(format!("/api/admin/v1/user-emails/{email_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
