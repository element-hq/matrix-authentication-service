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
    admin::{call_context::CallContext, params::UlidPathParam, response::ErrorResponse},
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Upstream OAuth 2.0 Link ID {0} not found")]
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
        .id("deleteUpstreamOAuthLink")
        .summary("Delete an upstream OAuth 2.0 link")
        .tag("upstream-oauth-link")
        .response_with::<204, (), _>(|t| t.description("Upstream OAuth 2.0 link was deleted"))
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::NotFound(Ulid::nil()));
            t.description("Upstream OAuth 2.0 link was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.delete", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    id: UlidPathParam,
) -> Result<StatusCode, RouteError> {
    let link = repo
        .upstream_oauth_link()
        .lookup(*id)
        .await?
        .ok_or(RouteError::NotFound(*id))?;

    repo.upstream_oauth_link().remove(&clock, link).await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_data_model::UpstreamOAuthAuthorizationSessionState;
    use sqlx::PgPool;
    use ulid::Ulid;

    use super::super::test_utils;
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

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        // Pretend it was linked by an authorization session
        let session = repo
            .upstream_oauth_session()
            .add(&mut rng, &state.clock, &provider, String::new(), None, None)
            .await
            .unwrap();

        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                String::from("subject1"),
                None,
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(&state.clock, session, &link, None, None, None)
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&link, &alice)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::delete(format!("/api/admin/v1/upstream-oauth-links/{}", link.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Verify that the link was deleted
        let request = Request::get(format!("/api/admin/v1/upstream-oauth-links/{}", link.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);

        // Verify that the session was marked as unlinked
        let mut repo = state.repository().await.unwrap();
        let session = repo
            .upstream_oauth_session()
            .lookup(session.id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            session.state,
            UpstreamOAuthAuthorizationSessionState::Unlinked { .. }
        ));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let link_id = Ulid::nil();
        let request = Request::delete(format!("/api/admin/v1/upstream-oauth-links/{link_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
