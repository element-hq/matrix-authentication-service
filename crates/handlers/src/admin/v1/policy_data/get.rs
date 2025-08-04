// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::PolicyData,
        params::UlidPathParam,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Policy data with ID {0} not found")]
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
        .id("getPolicyData")
        .summary("Get policy data by ID")
        .tag("policy-data")
        .response_with::<200, Json<SingleResponse<PolicyData>>, _>(|t| {
            let [sample, ..] = PolicyData::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("Policy data was found").example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("Policy data was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.policy_data.get", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<PolicyData>>, RouteError> {
    let policy_data = repo
        .policy_data()
        .get()
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    Ok(Json(SingleResponse::new_canonical(policy_data.into())))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let policy_data = repo
            .policy_data()
            .set(
                &mut rng,
                &state.clock,
                serde_json::json!({"hello": "world"}),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get(format!("/api/admin/v1/policy-data/{}", policy_data.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "policy-data",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "data": {
                "hello": "world"
              }
            },
            "links": {
              "self": "/api/admin/v1/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "###);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::get(format!("/api/admin/v1/policy-data/{}", Ulid::nil()))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Policy data with ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }
}
