// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::str::FromStr;

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use axum_extra::extract::{Query, QueryRejection};
use axum_macros::FromRequestParts;
use chrono::{DateTime, Utc};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{Page, oauth2::OAuth2SessionFilter};
use oauth2_types::scope::{Scope, ScopeToken};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{OAuth2Session, Resource},
        params::{IncludeCount, Pagination},
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum OAuth2SessionStatus {
    Active,
    Finished,
}

impl std::fmt::Display for OAuth2SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Finished => write!(f, "finished"),
        }
    }
}

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
#[serde(rename = "OAuth2SessionFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve the items for the given user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Retrieve the items for the given client(s)
    ///
    /// This parameter may be repeated to filter on multiple clients at
    /// once (sessions matching any of the given clients are returned).
    #[serde(default, rename = "filter[client]")]
    #[schemars(with = "Vec<crate::admin::schema::Ulid>")]
    client: Vec<Ulid>,

    /// Retrieve the items only for a specific client kind
    #[serde(rename = "filter[client-kind]")]
    client_kind: Option<OAuth2ClientKind>,

    /// Retrieve the items started from the given browser session
    #[serde(rename = "filter[user-session]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    user_session: Option<Ulid>,

    /// Retrieve the items with the given scope
    #[serde(default, rename = "filter[scope]")]
    scope: Vec<String>,

    /// Retrieve the items with the given status
    ///
    /// Defaults to retrieve all sessions, including finished ones.
    ///
    /// * `active`: Only retrieve active sessions
    ///
    /// * `finished`: Only retrieve finished sessions
    #[serde(rename = "filter[status]")]
    status: Option<OAuth2SessionStatus>,

    /// Retrieve sessions created strictly before the given time
    #[serde(rename = "filter[created-before]")]
    created_before: Option<DateTime<Utc>>,

    /// Retrieve sessions created strictly after the given time
    #[serde(rename = "filter[created-after]")]
    created_after: Option<DateTime<Utc>>,

    /// Retrieve sessions last active strictly before the given time
    #[serde(rename = "filter[last-active-before]")]
    last_active_before: Option<DateTime<Utc>>,

    /// Retrieve sessions last active strictly after the given time
    #[serde(rename = "filter[last-active-after]")]
    last_active_after: Option<DateTime<Utc>>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(user) = self.user {
            write!(f, "{sep}filter[user]={user}")?;
            sep = '&';
        }

        for client in &self.client {
            write!(f, "{sep}filter[client]={client}")?;
            sep = '&';
        }

        if let Some(client_kind) = self.client_kind {
            write!(f, "{sep}filter[client-kind]={client_kind}")?;
            sep = '&';
        }

        if let Some(user_session) = self.user_session {
            write!(f, "{sep}filter[user-session]={user_session}")?;
            sep = '&';
        }

        for scope in &self.scope {
            write!(f, "{sep}filter[scope]={scope}")?;
            sep = '&';
        }

        if let Some(status) = self.status {
            write!(f, "{sep}filter[status]={status}")?;
            sep = '&';
        }

        if let Some(created_before) = self.created_before {
            write!(
                f,
                "{sep}filter[created-before]={}",
                created_before.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            sep = '&';
        }

        if let Some(created_after) = self.created_after {
            write!(
                f,
                "{sep}filter[created-after]={}",
                created_after.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            sep = '&';
        }

        if let Some(last_active_before) = self.last_active_before {
            write!(
                f,
                "{sep}filter[last-active-before]={}",
                last_active_before.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
            sep = '&';
        }

        if let Some(last_active_after) = self.last_active_after {
            write!(
                f,
                "{sep}filter[last-active-after]={}",
                last_active_after.format("%Y-%m-%dT%H:%M:%SZ")
            )?;
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

    #[error("User ID {0} not found")]
    UserNotFound(Ulid),

    #[error("Client ID {0} not found")]
    ClientNotFound(Ulid),

    #[error("User session ID {0} not found")]
    UserSessionNotFound(Ulid),

    #[error("Invalid filter parameters")]
    InvalidFilter(#[from] QueryRejection),

    #[error("Invalid scope {0:?} in filter parameters")]
    InvalidScope(String),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, RouteError::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound(_) | Self::ClientNotFound(_) | Self::UserSessionNotFound(_) => {
                StatusCode::NOT_FOUND
            }
            Self::InvalidScope(_) | Self::InvalidFilter(_) => StatusCode::BAD_REQUEST,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("listOAuth2Sessions")
        .summary("List OAuth 2.0 sessions")
        .description("Retrieve a list of OAuth 2.0 sessions.
Note that by default, all sessions, including finished ones are returned, with the oldest first.
Use the `filter[status]` parameter to filter the sessions by their status and `page[last]` parameter to retrieve the last N sessions.
The `filter[client]` parameter may be repeated to filter on multiple clients at once.")
        .tag("oauth2-session")
        .response_with::<200, Json<PaginatedResponse<OAuth2Session>>, _>(|t| {
            let sessions = OAuth2Session::samples();
            let pagination = mas_storage::Pagination::first(sessions.len());
            let page = Page {
                edges: sessions
                    .into_iter()
                    .map(|node| mas_storage::pagination::Edge {
                        cursor: node.id(),
                        node,
                    })
                    .collect(),
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of OAuth 2.0 sessions")
                .example(PaginatedResponse::for_page(
                    page,
                    pagination,
                    Some(42),
                    OAuth2Session::PATH,
                ))
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserNotFound(Ulid::nil()));
            t.description("User was not found").example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::InvalidScope("not a valid scope".to_owned()));
            t.description("Invalid scope").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.oauth2_sessions.list", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Pagination(pagination, include_count): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<OAuth2Session>>, RouteError> {
    let base = format!("{path}{params}", path = OAuth2Session::PATH);
    let base = include_count.add_to_base(&base);
    let filter = OAuth2SessionFilter::default();

    // Load the user from the filter
    let user = if let Some(user_id) = params.user {
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .ok_or(RouteError::UserNotFound(user_id))?;

        Some(user)
    } else {
        None
    };

    let filter = match &user {
        Some(user) => filter.for_user(user),
        None => filter,
    };

    let mut clients = Vec::with_capacity(params.client.len());
    for client_id in params.client {
        let client = repo
            .oauth2_client()
            .lookup(client_id)
            .await?
            .ok_or(RouteError::ClientNotFound(client_id))?;
        clients.push(client);
    }
    let client_refs: Vec<&_> = clients.iter().collect();

    let filter = if client_refs.is_empty() {
        filter
    } else {
        filter.for_clients(&client_refs)
    };

    let filter = match params.client_kind {
        Some(OAuth2ClientKind::Dynamic) => filter.only_dynamic_clients(),
        Some(OAuth2ClientKind::Static) => filter.only_static_clients(),
        None => filter,
    };

    let user_session = if let Some(user_session_id) = params.user_session {
        let user_session = repo
            .browser_session()
            .lookup(user_session_id)
            .await?
            .ok_or(RouteError::UserSessionNotFound(user_session_id))?;

        Some(user_session)
    } else {
        None
    };

    let filter = match &user_session {
        Some(user_session) => filter.for_browser_session(user_session),
        None => filter,
    };

    let scope: Scope = params
        .scope
        .into_iter()
        .map(|s| ScopeToken::from_str(&s).map_err(|_| RouteError::InvalidScope(s)))
        .collect::<Result<_, _>>()?;

    let filter = if scope.is_empty() {
        filter
    } else {
        filter.with_scope(&scope)
    };

    let filter = match params.status {
        Some(OAuth2SessionStatus::Active) => filter.active_only(),
        Some(OAuth2SessionStatus::Finished) => filter.finished_only(),
        None => filter,
    };

    let filter = if let Some(created_before) = params.created_before {
        filter.with_created_before(created_before)
    } else {
        filter
    };

    let filter = if let Some(created_after) = params.created_after {
        filter.with_created_after(created_after)
    } else {
        filter
    };

    let filter = if let Some(last_active_before) = params.last_active_before {
        filter.with_last_active_before(last_active_before)
    } else {
        filter
    };

    let filter = if let Some(last_active_after) = params.last_active_after {
        filter.with_last_active_after(last_active_after)
    } else {
        filter
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .oauth2_session()
                .list(filter, pagination)
                .await?
                .map(OAuth2Session::from);
            let count = repo.oauth2_session().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .oauth2_session()
                .list(filter, pagination)
                .await?
                .map(OAuth2Session::from);
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.oauth2_session().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use mas_data_model::Clock;
    use oauth2_types::{
        requests::GrantType,
        scope::{OPENID, Scope},
    };
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_oauth2_simple_session_list(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        // We already have a session because of the token above
        let request = Request::get("/api/admin/v1/oauth2-sessions")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MKGTBNZ16RDR3PVY"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/oauth2-sessions?page[first]=10",
            "first": "/api/admin/v1/oauth2-sessions?page[first]=10",
            "last": "/api/admin/v1/oauth2-sessions?page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/api/admin/v1/oauth2-sessions?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
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
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MKGTBNZ16RDR3PVY"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/oauth2-sessions?count=false&page[first]=10",
            "first": "/api/admin/v1/oauth2-sessions?count=false&page[first]=10",
            "last": "/api/admin/v1/oauth2-sessions?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/oauth2-sessions?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/api/admin/v1/oauth2-sessions?count=only"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_oauth2_session_list_by_last_active(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &state.clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("Test client".to_owned()),
                Some("https://example.com/logo.png".parse().unwrap()),
                Some("https://example.com/".parse().unwrap()),
                Some("https://example.com/policy".parse().unwrap()),
                Some("https://example.com/tos".parse().unwrap()),
                Some("https://example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        let session = repo
            .oauth2_session()
            .add_from_client_credentials(
                &mut rng,
                &state.clock,
                &client,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();

        state.clock.advance(Duration::minutes(5));
        let activity_at = state.clock.now();
        repo.oauth2_session()
            .record_batch_activity(vec![(session.id, activity_at, None)])
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Sessions last active after `activity_at - 1m` should include our
        // session.
        let threshold = activity_at - Duration::minutes(1);
        let request = Request::get(format!(
            "/api/admin/v1/oauth2-sessions?filter[last-active-after]={}",
            threshold.format("%Y-%m-%dT%H:%M:%SZ")
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        let ids: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&session.id.to_string().as_str()));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_oauth2_session_list_by_created_at(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &state.clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("Test client".to_owned()),
                Some("https://example.com/logo.png".parse().unwrap()),
                Some("https://example.com/".parse().unwrap()),
                Some("https://example.com/policy".parse().unwrap()),
                Some("https://example.com/tos".parse().unwrap()),
                Some("https://example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        // Two extra sessions, one before and one after a cutoff. (There's
        // also one pre-existing session from the admin token.)
        repo.oauth2_session()
            .add_from_client_credentials(
                &mut rng,
                &state.clock,
                &client,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        state.clock.advance(Duration::minutes(1));
        let cutoff = state.clock.now();
        state.clock.advance(Duration::minutes(1));
        let new_session = repo
            .oauth2_session()
            .add_from_client_credentials(
                &mut rng,
                &state.clock,
                &client,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Sessions created after the cutoff: only the second one
        let request = Request::get(format!(
            "/api/admin/v1/oauth2-sessions?filter[created-after]={}",
            cutoff.format("%Y-%m-%dT%H:%M:%SZ")
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 1);
        let ids: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec![new_session.id.to_string()]);
    }

    /// Provisions two extra clients and a session for each, then verifies
    /// that listing with two `filter[client]` query parameters returns both
    /// sessions (and excludes the admin session for the third, unrelated
    /// client).
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_oauth2_session_list_multiple_clients(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision two clients and a session for each, both using the
        // client_credentials flow so that they don't depend on a user.
        let mut repo = state.repository().await.unwrap();
        let client_a = repo
            .oauth2_client()
            .add(
                &mut rng,
                &state.clock,
                vec!["https://a.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("client a".to_owned()),
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
        let client_b = repo
            .oauth2_client()
            .add(
                &mut rng,
                &state.clock,
                vec!["https://b.example.com/redirect".parse().unwrap()],
                None,
                None,
                None,
                vec![GrantType::ClientCredentials],
                Some("client b".to_owned()),
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

        let scope: Scope = "urn:mas:admin".parse().unwrap();
        let session_a = repo
            .oauth2_session()
            .add_from_client_credentials(&mut rng, &state.clock, &client_a, scope.clone())
            .await
            .unwrap();
        let session_b = repo
            .oauth2_session()
            .add_from_client_credentials(&mut rng, &state.clock, &client_b, scope.clone())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Filter on both new clients. The admin session (a third client) must
        // not appear in the result.
        let url = format!(
            "/api/admin/v1/oauth2-sessions?filter[client]={}&filter[client]={}",
            client_a.id, client_b.id,
        );
        let request = Request::get(&url).bearer(&token).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["meta"]["count"], 2);
        let ids: Vec<&str> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        let session_a_id = session_a.id.to_string();
        let session_b_id = session_b.id.to_string();
        assert!(ids.contains(&session_a_id.as_str()));
        assert!(ids.contains(&session_b_id.as_str()));
        assert_eq!(ids.len(), 2);

        // The self/first/last links should preserve both filter[client] segments
        let self_link = body["links"]["self"].as_str().unwrap();
        assert!(self_link.contains(&format!("filter[client]={}", client_a.id)));
        assert!(self_link.contains(&format!("filter[client]={}", client_b.id)));
    }
}
