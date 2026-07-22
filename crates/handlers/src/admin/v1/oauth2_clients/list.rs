// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use axum_extra::extract::{Query, QueryRejection};
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{Page, oauth2::OAuth2ClientFilter};
use oauth2_types::requests::GrantType;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    admin::{
        call_context::CallContext,
        model::{OAuth2Client, Resource},
        params::{IncludeCount, Pagination},
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum OAuth2ClientKind {
    Dynamic,
    Static,
}

impl std::fmt::Display for OAuth2ClientKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dynamic => write!(f, "dynamic"),
            Self::Static => write!(f, "static"),
        }
    }
}

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[serde(rename = "OAuth2ClientFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve only clients of the given kind
    ///
    /// * `dynamic`: clients registered via the dynamic-client-registration
    ///   endpoint
    ///
    /// * `static`: clients declared in the configuration file
    #[serde(rename = "filter[client-kind]")]
    client_kind: Option<OAuth2ClientKind>,

    /// Substring (case-insensitive) match on the client's `client_name`
    #[serde(rename = "filter[client-name]")]
    client_name: Option<String>,

    /// Substring (case-insensitive) match on the client's `client_uri`
    #[serde(rename = "filter[client-uri]")]
    client_uri: Option<String>,

    /// Retrieve only clients which support the given grant type
    ///
    /// e.g. `authorization_code`, `client_credentials`,
    /// `urn:ietf:params:oauth:grant-type:device_code`
    #[serde(rename = "filter[grant-type]")]
    #[schemars(with = "Option<String>")]
    grant_type: Option<GrantType>,

    /// Retrieve only clients which have (`true`) or don't have (`false`) at
    /// least one active OAuth 2.0 session
    #[serde(rename = "filter[has-active-sessions]")]
    has_active_sessions: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(client_kind) = self.client_kind {
            write!(f, "{sep}filter[client-kind]={client_kind}")?;
            sep = '&';
        }

        if let Some(client_name) = &self.client_name {
            write!(f, "{sep}filter[client-name]={client_name}")?;
            sep = '&';
        }

        if let Some(client_uri) = &self.client_uri {
            write!(f, "{sep}filter[client-uri]={client_uri}")?;
            sep = '&';
        }

        if let Some(grant_type) = &self.grant_type {
            write!(f, "{sep}filter[grant-type]={grant_type}")?;
            sep = '&';
        }

        if let Some(has_active_sessions) = self.has_active_sessions {
            write!(f, "{sep}filter[has-active-sessions]={has_active_sessions}")?;
            sep = '&';
        }

        let _ = sep;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Invalid filter parameters")]
    InvalidFilter(#[from] QueryRejection),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidFilter(_) => StatusCode::BAD_REQUEST,
        };

        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("listOAuth2Clients")
        .summary("List OAuth 2.0 clients")
        .description(
            "Retrieve a paginated list of OAuth 2.0 clients registered with this service.
Use the `filter[client-kind]` parameter to restrict the response to either static (configured) or dynamic (registered at runtime) clients,
the `filter[client-name]`/`filter[client-uri]` parameters for a case-insensitive substring search,
the `filter[grant-type]` parameter to restrict to clients which support a given grant type,
and the `filter[has-active-sessions]` parameter to restrict to clients which have (or don't have) an active session.",
        )
        .tag("oauth2-client")
        .response_with::<200, Json<PaginatedResponse<OAuth2Client>>, _>(|t| {
            let clients = OAuth2Client::samples();
            let pagination = mas_storage::Pagination::first(clients.len());
            let page = Page {
                edges: clients
                    .into_iter()
                    .map(|node| mas_storage::pagination::Edge {
                        cursor: node.id(),
                        node,
                    })
                    .collect(),
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of OAuth 2.0 clients")
                .example(PaginatedResponse::for_page(
                    page,
                    pagination,
                    Some(42),
                    OAuth2Client::PATH,
                ))
        })
        .response_with::<400, RouteError, _>(|t| {
            // Try to construct a query-rejection example without actually parsing —
            // we only use it for the description text.
            t.description("Invalid filter parameters")
        })
}

#[tracing::instrument(name = "handler.admin.v1.oauth2_clients.list", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Pagination(pagination, include_count): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<OAuth2Client>>, RouteError> {
    let base = format!("{path}{params}", path = OAuth2Client::PATH);
    let base = include_count.add_to_base(&base);
    let mut filter = OAuth2ClientFilter::new();

    filter = match params.client_kind {
        Some(OAuth2ClientKind::Dynamic) => filter.only_dynamic_clients(),
        Some(OAuth2ClientKind::Static) => filter.only_static_clients(),
        None => filter,
    };

    if let Some(client_name) = params.client_name.as_deref() {
        filter = filter.matching_client_name(client_name);
    }

    if let Some(client_uri) = params.client_uri.as_deref() {
        filter = filter.matching_client_uri(client_uri);
    }

    if let Some(grant_type) = &params.grant_type {
        filter = filter.with_grant_type(grant_type);
    }

    if let Some(has_active_sessions) = params.has_active_sessions {
        filter = filter.with_active_sessions(has_active_sessions);
    }

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .oauth2_client()
                .list(filter, pagination)
                .await?
                .map(OAuth2Client::from);
            let count = repo.oauth2_client().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .oauth2_client()
                .list(filter, pagination)
                .await?
                .map(OAuth2Client::from);
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.oauth2_client().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_data_model::{Clock, UlidExt as _};
    use mas_iana::oauth::OAuthClientAuthenticationMethod;
    use mas_storage::RepositoryAccess;
    use oauth2_types::requests::GrantType;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    async fn create_test_clients(state: &mut TestState) {
        let mut repo = state.repository().await.unwrap();

        // Add a dynamically-registered client
        repo.oauth2_client()
            .add(
                &mut state.rng(),
                &state.clock,
                vec!["https://first.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("First Client".to_owned()),
                None,
                Some("https://first.example.com/".parse().unwrap()),
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

        // Add another dynamically-registered client
        repo.oauth2_client()
            .add(
                &mut state.rng(),
                &state.clock,
                vec!["https://second.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("Second Client".to_owned()),
                None,
                Some("https://second.example.com/".parse().unwrap()),
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

        // Add a static client
        let static_id = ulid::Ulid::from_datetime_with_rng(state.clock.now(), &mut state.rng());
        repo.oauth2_client()
            .upsert_static(
                static_id,
                Some("Static Client".to_owned()),
                OAuthClientAuthenticationMethod::None,
                None,
                None,
                None,
                vec!["https://static.example.com/redirect".parse().unwrap()],
                false,
            )
            .await
            .unwrap();

        Box::new(repo).save().await.unwrap();
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list_all_clients(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        create_test_clients(&mut state).await;

        let request = Request::get("/api/admin/v1/oauth2-clients")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        // There's also the static client used by the admin token itself
        assert!(body["data"].as_array().unwrap().len() >= 3);
        assert_eq!(body["data"][0]["type"], "oauth2-client");
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_static(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        create_test_clients(&mut state).await;

        let request = Request::get("/api/admin/v1/oauth2-clients?filter[client-kind]=static")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        // The "Static Client" plus any clients created by the test harness as static
        for client in body["data"].as_array().unwrap() {
            assert_eq!(client["attributes"]["is_static"], true);
        }
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_dynamic(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        create_test_clients(&mut state).await;

        let request = Request::get("/api/admin/v1/oauth2-clients?filter[client-kind]=dynamic")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let data = body["data"].as_array().unwrap();
        // Our two dynamic clients, plus the one created by token_with_scope
        assert!(data.len() >= 2);
        for client in data {
            assert_eq!(client["attributes"]["is_static"], false);
        }
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_client_name(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        create_test_clients(&mut state).await;

        let request = Request::get("/api/admin/v1/oauth2-clients?filter[client-name]=first")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let data = body["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["attributes"]["client_name"], "First Client");
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_client_uri(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        create_test_clients(&mut state).await;

        let request = Request::get("/api/admin/v1/oauth2-clients?filter[client-uri]=second")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let data = body["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["attributes"]["client_name"], "Second Client");
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_grant_type(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // One authorization_code client and one client_credentials client
        let mut repo = state.repository().await.unwrap();
        repo.oauth2_client()
            .add(
                &mut state.rng(),
                &state.clock,
                vec!["https://code.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some("Code client".to_owned()),
                None,
                None,
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
        repo.oauth2_client()
            .add(
                &mut state.rng(),
                &state.clock,
                vec![],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("Credentials client".to_owned()),
                None,
                None,
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
        Box::new(repo).save().await.unwrap();

        // client_credentials: only the credentials client (the admin token's
        // own client uses client_credentials too, so match by name)
        let request =
            Request::get("/api/admin/v1/oauth2-clients?filter[grant-type]=client_credentials")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let names: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["attributes"]["client_name"].as_str().unwrap_or_default())
            .collect();
        assert!(names.contains(&"Credentials client"));
        assert!(!names.contains(&"Code client"));

        // device_code: no client supports it
        let request =
            Request::get("/api/admin/v1/oauth2-clients?count=only&filter[grant-type]=urn:ietf:params:oauth:grant-type:device_code")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 0);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_filter_by_has_active_sessions(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // A client with an active client-credentials session, and one without
        let mut repo = state.repository().await.unwrap();
        let with_session = repo
            .oauth2_client()
            .add(
                &mut state.rng(),
                &state.clock,
                vec![],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("Client with session".to_owned()),
                None,
                None,
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
        repo.oauth2_client()
            .add(
                &mut state.rng(),
                &state.clock,
                vec![],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("Client without session".to_owned()),
                None,
                None,
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
        repo.oauth2_session()
            .add_from_client_credentials(
                &mut state.rng(),
                &state.clock,
                &with_session,
                "urn:mas:admin".parse().unwrap(),
            )
            .await
            .unwrap();
        Box::new(repo).save().await.unwrap();

        // Clients with an active session: includes our client and the admin
        // token's own client, but not "Client without session"
        let request = Request::get("/api/admin/v1/oauth2-clients?filter[has-active-sessions]=true")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let names: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["attributes"]["client_name"].as_str().unwrap_or_default())
            .collect();
        assert!(names.contains(&"Client with session"));
        assert!(!names.contains(&"Client without session"));

        // Clients without an active session: includes "Client without session"
        let request =
            Request::get("/api/admin/v1/oauth2-clients?filter[has-active-sessions]=false")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let names: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["attributes"]["client_name"].as_str().unwrap_or_default())
            .collect();
        assert!(names.contains(&"Client without session"));
        assert!(!names.contains(&"Client with session"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invalid_filter(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::get("/api/admin/v1/oauth2-clients?filter[client-kind]=invalid")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
