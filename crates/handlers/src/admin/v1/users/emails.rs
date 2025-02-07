// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use aide::{transform::TransformOperation, OperationIo};
use axum::{response::IntoResponse, Json};
use hyper::StatusCode;
use ulid::Ulid;
use mas_storage::{Pagination, RepositoryAccess};
use mas_storage::user::{UserEmailFilter, UserEmailRepository};
use crate::{
    admin::{
        call_context::CallContext,
        model::User,
        params::UlidPathParam,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};
use crate::admin::model::UserEmail;

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("User ID {0} not found")]
    NotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("getUserEmails")
        .summary("Get a user's emails")
        .tag("user")
        .response_with::<200, Json<SingleResponse<Vec<UserEmail>>>, _>(|t| {
            let [sample, ..] = UserEmail::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("User was found").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("User was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.get_emails", skip_all, err)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<Vec<UserEmail>>>, RouteError> {
    let user = repo
        .user()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    let emails: Vec<UserEmail> = repo
        .user_email()
        .all(&user)
        .await?
        .iter()
        .map(|e| UserEmail::from(e))
        .into();

    Ok(Json(SingleResponse::new_canonical(emails)))
}
