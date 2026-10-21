// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
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

    #[error("User session limit override ID {0} not found")]
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
        .id("deleteUserSessionLimitOverride")
        .summary("Delete a user session limit override")
        .tag("user-session-limit-override")
        .response_with::<204, (), _>(|t| t.description("User session limit override was deleted"))
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User session limit override was not found")
                .example(response)
        })
}

#[tracing::instrument(
    name = "handler.admin.v1.user_session_limit_overrides.delete",
    skip_all
)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    id: UlidPathParam,
) -> Result<StatusCode, RouteError> {
    let override_row = repo
        .user_session_limit_override()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    repo.user_session_limit_override()
        .remove(override_row)
        .await?;
    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

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

        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let override_row = repo
            .user_session_limit_override()
            .add(
                &mut rng,
                &state.clock,
                &alice,
                None,
                NonZeroU64::new(3).unwrap(),
                NonZeroU64::new(5).unwrap(),
            )
            .await
            .unwrap();
        let id = override_row.id;
        repo.save().await.unwrap();

        let request = Request::delete(format!("/api/admin/v1/user-session-limit-overrides/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        let request = Request::get(format!("/api/admin/v1/user-session-limit-overrides/{id}"))
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

        let request = Request::delete(format!(
            "/api/admin/v1/user-session-limit-overrides/{}",
            Ulid::nil()
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
