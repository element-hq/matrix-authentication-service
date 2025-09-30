// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::str::FromStr;

use aide::{OperationIo, transform::TransformOperation};
use axum::{
    Json,
    extract::{Query, rejection::QueryRejection},
    response::IntoResponse,
};
use axum_macros::FromRequestParts;
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
        params::Pagination,
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

    /// Retrieve the items for the given client
    #[serde(rename = "filter[client]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    client: Option<Ulid>,

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
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(user) = self.user {
            write!(f, "{sep}filter[user]={user}")?;
            sep = '&';
        }

        if let Some(client) = self.client {
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
Use the `filter[status]` parameter to filter the sessions by their status and `page[last]` parameter to retrieve the last N sessions.")
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
                .example(PaginatedResponse::new(
                    page,
                    pagination,
                    42,
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
    Pagination(pagination): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<OAuth2Session>>, RouteError> {
    let base = format!("{path}{params}", path = OAuth2Session::PATH);
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

    let client = if let Some(client_id) = params.client {
        let client = repo
            .oauth2_client()
            .lookup(client_id)
            .await?
            .ok_or(RouteError::ClientNotFound(client_id))?;

        Some(client)
    } else {
        None
    };

    let filter = match &client {
        Some(client) => filter.for_client(client),
        None => filter,
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

    let page = repo.oauth2_session().list(filter, pagination).await?;
    let count = repo.oauth2_session().count(filter).await?;

    Ok(Json(PaginatedResponse::new(
        page.map(OAuth2Session::from),
        pagination,
        count,
        &base,
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
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
    }
}
