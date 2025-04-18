// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::CompatSession,
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

    #[error("Compatibility session ID {0} not found")]
    NotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, RouteError::Internal(_));
        let status = match &self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };

        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("getCompatSession")
        .summary("Get a compatibility session")
        .tag("compat-session")
        .response_with::<200, Json<SingleResponse<CompatSession>>, _>(|t| {
            let [sample, ..] = CompatSession::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("Compatibility session was found")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("Compatibility session was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.compat_sessions.get", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<CompatSession>>, RouteError> {
    let session = repo
        .compat_session()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    let sso_login = repo.compat_sso_login().find_for_session(&session).await?;

    Ok(Json(SingleResponse::new_canonical(CompatSession::from((
        session, sso_login,
    )))))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use mas_data_model::Device;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision a user and a compat session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(&mut rng, &state.clock, &user, device, None, false)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let session_id = session.id;
        let request = Request::get(format!("/api/admin/v1/compat-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "compat-session",
            "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
            "attributes": {
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "device_id": "TpLoieH5Ie",
              "user_session_id": null,
              "redirect_uri": null,
              "created_at": "2022-01-16T14:40:00Z",
              "user_agent": null,
              "last_active_at": null,
              "last_active_ip": null,
              "finished_at": null
            },
            "links": {
              "self": "/api/admin/v1/compat-sessions/01FSHN9AG0QHEHKX2JNQ2A2D07"
            }
          },
          "links": {
            "self": "/api/admin/v1/compat-sessions/01FSHN9AG0QHEHKX2JNQ2A2D07"
          }
        }
        "###);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let session_id = Ulid::nil();
        let request = Request::get(format!("/api/admin/v1/compat-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
