// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
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
        model::OAuth2Session,
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

    #[error("OAuth 2.0 session ID {0} not found")]
    NotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, RouteError::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("getOAuth2Session")
        .summary("Get an OAuth 2.0 session")
        .tag("oauth2-session")
        .response_with::<200, Json<SingleResponse<OAuth2Session>>, _>(|t| {
            let [sample, ..] = OAuth2Session::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("OAuth 2.0 session was found")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("OAuth 2.0 session was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.oauth2_session.get", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<OAuth2Session>>, RouteError> {
    let session = repo
        .oauth2_session()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    Ok(Json(SingleResponse::new_canonical(OAuth2Session::from(
        session,
    ))))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_data_model::AccessToken;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // state.token_with_scope did create a session, so we can get it here
        let mut repo = state.repository().await.unwrap();
        let AccessToken { session_id, .. } = repo
            .oauth2_access_token()
            .find_by_token(&token)
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get(format!("/api/admin/v1/oauth2-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "oauth2-session");
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "oauth2-session",
            "id": "01FSHN9AG0MKGTBNZ16RDR3PVY",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "finished_at": null,
              "user_id": null,
              "user_session_id": null,
              "client_id": "01FSHN9AG0FAQ50MT1E9FFRPZR",
              "scope": "urn:mas:admin",
              "user_agent": null,
              "last_active_at": null,
              "last_active_ip": null,
              "human_name": null
            },
            "links": {
              "self": "/api/admin/v1/oauth2-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
            }
          },
          "links": {
            "self": "/api/admin/v1/oauth2-sessions/01FSHN9AG0MKGTBNZ16RDR3PVY"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let session_id = Ulid::nil();
        let request = Request::get(format!("/api/admin/v1/oauth2-sessions/{session_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
