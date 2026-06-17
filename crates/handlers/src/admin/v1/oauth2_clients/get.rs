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
    admin::{
        call_context::CallContext,
        model::OAuth2Client,
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

    #[error("OAuth 2.0 client ID {0} not found")]
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
        .id("getOAuth2Client")
        .summary("Get an OAuth 2.0 client")
        .tag("oauth2-client")
        .response_with::<200, Json<SingleResponse<OAuth2Client>>, _>(|t| {
            let [sample, ..] = OAuth2Client::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("OAuth 2.0 client was found")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("OAuth 2.0 client was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.oauth2_client.get", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    id: UlidPathParam,
) -> Result<Json<SingleResponse<OAuth2Client>>, RouteError> {
    let client = repo
        .oauth2_client()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    Ok(Json(SingleResponse::new_canonical(OAuth2Client::from(
        client,
    ))))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_storage::RepositoryAccess;
    use oauth2_types::requests::GrantType;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // Add a client we know the ID of
        let mut repo = state.repository().await.unwrap();
        let client = repo
            .oauth2_client()
            .add(
                &mut state.rng(),
                &state.clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("Example Client".to_owned()),
                None,
                Some("https://example.com/".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let client_id = client.id;
        Box::new(repo).save().await.unwrap();

        let request = Request::get(format!("/api/admin/v1/oauth2-clients/{client_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["data"]["type"], "oauth2-client");
        assert_eq!(body["data"]["attributes"]["client_name"], "Example Client");
        assert_eq!(body["data"]["attributes"]["is_static"], false);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let id = Ulid::nil();
        let request = Request::get(format!("/api/admin/v1/oauth2-clients/{id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
