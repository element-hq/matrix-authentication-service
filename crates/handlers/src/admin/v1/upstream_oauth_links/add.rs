// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::BoxRng;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, UpstreamOAuthLink},
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Upstream Oauth 2.0 Provider ID {0} with subject {1} is already linked to a user")]
    LinkAlreadyExists(Ulid, String),

    #[error("User ID {0} not found")]
    UserNotFound(Ulid),

    #[error("Upstream OAuth 2.0 Provider ID {0} not found")]
    ProviderNotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::LinkAlreadyExists(_, _) => StatusCode::CONFLICT,
            Self::UserNotFound(_) | Self::ProviderNotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

/// # JSON payload for the `POST /api/admin/v1/upstream-oauth-links`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUpstreamOauthLinkRequest")]
pub struct Request {
    /// The ID of the user to which the link should be added.
    #[schemars(with = "crate::admin::schema::Ulid")]
    user_id: Ulid,

    /// The ID of the upstream provider to which the link is for.
    #[schemars(with = "crate::admin::schema::Ulid")]
    provider_id: Ulid,

    /// The subject (sub) claim of the user on the provider.
    subject: String,

    /// A human readable account name.
    human_account_name: Option<String>,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("addUpstreamOAuthLink")
        .summary("Add an upstream OAuth 2.0 link")
        .tag("upstream-oauth-link")
        .response_with::<200, Json<SingleResponse<UpstreamOAuthLink>>, _>(|t| {
            let [sample, ..] = UpstreamOAuthLink::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("An existing Upstream OAuth 2.0 link was associated to a user")
                .example(response)
        })
        .response_with::<201, Json<SingleResponse<UpstreamOAuthLink>>, _>(|t| {
            let [sample, ..] = UpstreamOAuthLink::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("A new Upstream OAuth 2.0 link was created")
                .example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let [provider_sample, ..] = UpstreamOAuthLink::samples();
            let response = ErrorResponse::from_error(&RouteError::LinkAlreadyExists(
                provider_sample.id(),
                String::from("subject1"),
            ));
            t.description("The subject from the provider is already linked to another user")
                .example(response)
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserNotFound(Ulid::nil()));
            t.description("User or provider was not found")
                .example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.post", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    NoApi(mut rng): NoApi<BoxRng>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<SingleResponse<UpstreamOAuthLink>>), RouteError> {
    // Find the user
    let user = repo
        .user()
        .lookup(params.user_id)
        .await?
        .ok_or(RouteError::UserNotFound(params.user_id))?;

    // Find the provider
    let provider = repo
        .upstream_oauth_provider()
        .lookup(params.provider_id)
        .await?
        .ok_or(RouteError::ProviderNotFound(params.provider_id))?;

    let maybe_link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, &params.subject)
        .await?;
    if let Some(mut link) = maybe_link {
        if link.user_id.is_some() {
            return Err(RouteError::LinkAlreadyExists(
                link.provider_id,
                link.subject,
            ));
        }

        repo.upstream_oauth_link()
            .associate_to_user(&link, &user)
            .await?;
        link.user_id = Some(user.id);

        repo.save().await?;

        return Ok((
            StatusCode::OK,
            Json(SingleResponse::new_canonical(link.into())),
        ));
    }

    let mut link = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &clock,
            &provider,
            params.subject,
            params.human_account_name,
        )
        .await?;

    repo.upstream_oauth_link()
        .associate_to_user(&link, &user)
        .await?;
    link.user_id = Some(user.id);

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(link.into())),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;
    use ulid::Ulid;

    use super::super::test_utils;
    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create(pool: PgPool) {
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

        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-link",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "provider_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "subject": "subject1",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_account_name": null
            },
            "links": {
              "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "###);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_association(pool: PgPool) {
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

        // Existing unfinished link
        repo.upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                String::from("subject1"),
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-link",
            "id": "01FSHN9AG09NMZYX8MFYH578R9",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "provider_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "subject": "subject1",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_account_name": null
            },
            "links": {
              "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
            }
          },
          "links": {
            "self": "/api/admin/v1/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
          }
        }
        "###);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_already_exists(pool: PgPool) {
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

        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
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

        repo.upstream_oauth_link()
            .associate_to_user(&link, &alice)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": bob.id,
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Upstream Oauth 2.0 Provider ID 01FSHN9AG09NMZYX8MFYH578R9 with subject subject1 is already linked to a user"
            }
          ]
        }
        "###);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_user_not_found(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": Ulid::nil(),
                "provider_id": provider.id,
                "subject": "subject1"
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
    async fn test_provider_not_found(pool: PgPool) {
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

        let request = Request::post("/api/admin/v1/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "provider_id": Ulid::nil(),
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Upstream OAuth 2.0 Provider ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }
}
