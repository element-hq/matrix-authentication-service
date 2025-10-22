// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use axum_extra::extract::{Query, QueryRejection};
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{Page, compat::CompatSessionFilter};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{CompatSession, Resource},
        params::{IncludeCount, Pagination},
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum CompatSessionStatus {
    Active,
    Finished,
}

impl std::fmt::Display for CompatSessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Finished => write!(f, "finished"),
        }
    }
}

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[serde(rename = "CompatSessionFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve the items for the given user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Retrieve the items started from the given browser session
    #[serde(rename = "filter[user-session]")]
    #[schemars(with = "Option<crate::admin::schema::Ulid>")]
    user_session: Option<Ulid>,

    /// Retrieve the items with the given status
    ///
    /// Defaults to retrieve all sessions, including finished ones.
    ///
    /// * `active`: Only retrieve active sessions
    ///
    /// * `finished`: Only retrieve finished sessions
    #[serde(rename = "filter[status]")]
    status: Option<CompatSessionStatus>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(user) = self.user {
            write!(f, "{sep}filter[user]={user}")?;
            sep = '&';
        }

        if let Some(user_session) = self.user_session {
            write!(f, "{sep}filter[user-session]={user_session}")?;
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

    #[error("User session ID {0} not found")]
    UserSessionNotFound(Ulid),

    #[error("Invalid filter parameters")]
    InvalidFilter(#[from] QueryRejection),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, RouteError::Internal(_));
        let status = match &self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound(_) | Self::UserSessionNotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidFilter(_) => StatusCode::BAD_REQUEST,
        };

        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("listCompatSessions")
        .summary("List compatibility sessions")
        .description("Retrieve a list of compatibility sessions.
Note that by default, all sessions, including finished ones are returned, with the oldest first.
Use the `filter[status]` parameter to filter the sessions by their status and `page[last]` parameter to retrieve the last N sessions.")
        .tag("compat-session")
        .response_with::<200, Json<PaginatedResponse<CompatSession>>, _>(|t| {
            let sessions = CompatSession::samples();
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

            t.description("Paginated response of compatibility sessions")
                .example(PaginatedResponse::for_page(
                    page,
                    pagination,
                    Some(42),
                    CompatSession::PATH,
                ))
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::UserNotFound(Ulid::nil()));
            t.description("User was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.compat_sessions.list", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Pagination(pagination, include_count): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<CompatSession>>, RouteError> {
    let base = format!("{path}{params}", path = CompatSession::PATH);
    let base = include_count.add_to_base(&base);
    let filter = CompatSessionFilter::default();

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

    let filter = match params.status {
        Some(CompatSessionStatus::Active) => filter.active_only(),
        Some(CompatSessionStatus::Finished) => filter.finished_only(),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo
                .compat_session()
                .list(filter, pagination)
                .await?
                .map(CompatSession::from);
            let count = repo.compat_session().count(filter).await?;
            PaginatedResponse::for_page(page, pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo
                .compat_session()
                .list(filter, pagination)
                .await?
                .map(CompatSession::from);
            PaginatedResponse::for_page(page, pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.compat_session().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use mas_data_model::Device;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_compat_session_list(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision two users, one compat session for each, and finish one of them
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        state.clock.advance(Duration::minutes(1));

        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();

        let device = Device::generate(&mut rng);
        repo.compat_session()
            .add(&mut rng, &state.clock, &alice, device, None, false, None)
            .await
            .unwrap();
        let device = Device::generate(&mut rng);

        state.clock.advance(Duration::minutes(1));

        let session = repo
            .compat_session()
            .add(&mut rng, &state.clock, &bob, device, None, false, None)
            .await
            .unwrap();
        state.clock.advance(Duration::minutes(1));
        repo.compat_session()
            .finish(&state.clock, session)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get("/api/admin/v1/compat-sessions")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "compat-session",
              "id": "01FSHNB530AAPR7PEV8KNBZD5Y",
              "attributes": {
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "device_id": "LoieH5Iecx",
                "user_session_id": null,
                "redirect_uri": null,
                "created_at": "2022-01-16T14:41:00Z",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "finished_at": null,
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/compat-sessions/01FSHNB530AAPR7PEV8KNBZD5Y"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHNB530AAPR7PEV8KNBZD5Y"
                }
              }
            },
            {
              "type": "compat-session",
              "id": "01FSHNCZP0PPF7X0EVMJNECPZW",
              "attributes": {
                "user_id": "01FSHNB530AJ6AC5HQ9X6H4RP4",
                "device_id": "ZXyvelQWW9",
                "user_session_id": null,
                "redirect_uri": null,
                "created_at": "2022-01-16T14:42:00Z",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "finished_at": "2022-01-16T14:43:00Z",
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/compat-sessions/01FSHNCZP0PPF7X0EVMJNECPZW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHNCZP0PPF7X0EVMJNECPZW"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/compat-sessions?page[first]=10",
            "first": "/api/admin/v1/compat-sessions?page[first]=10",
            "last": "/api/admin/v1/compat-sessions?page[last]=10"
          }
        }
        "#);

        // Filter by user
        let request = Request::get(format!(
            "/api/admin/v1/compat-sessions?filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "compat-session",
              "id": "01FSHNB530AAPR7PEV8KNBZD5Y",
              "attributes": {
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "device_id": "LoieH5Iecx",
                "user_session_id": null,
                "redirect_uri": null,
                "created_at": "2022-01-16T14:41:00Z",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "finished_at": null,
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/compat-sessions/01FSHNB530AAPR7PEV8KNBZD5Y"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHNB530AAPR7PEV8KNBZD5Y"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/compat-sessions?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "first": "/api/admin/v1/compat-sessions?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "last": "/api/admin/v1/compat-sessions?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[last]=10"
          }
        }
        "#);

        // Filter by status (active)
        let request = Request::get("/api/admin/v1/compat-sessions?filter[status]=active")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "compat-session",
              "id": "01FSHNB530AAPR7PEV8KNBZD5Y",
              "attributes": {
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "device_id": "LoieH5Iecx",
                "user_session_id": null,
                "redirect_uri": null,
                "created_at": "2022-01-16T14:41:00Z",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "finished_at": null,
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/compat-sessions/01FSHNB530AAPR7PEV8KNBZD5Y"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHNB530AAPR7PEV8KNBZD5Y"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/compat-sessions?filter[status]=active&page[first]=10",
            "first": "/api/admin/v1/compat-sessions?filter[status]=active&page[first]=10",
            "last": "/api/admin/v1/compat-sessions?filter[status]=active&page[last]=10"
          }
        }
        "#);

        // Filter by status (finished)
        let request = Request::get("/api/admin/v1/compat-sessions?filter[status]=finished")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "compat-session",
              "id": "01FSHNCZP0PPF7X0EVMJNECPZW",
              "attributes": {
                "user_id": "01FSHNB530AJ6AC5HQ9X6H4RP4",
                "device_id": "ZXyvelQWW9",
                "user_session_id": null,
                "redirect_uri": null,
                "created_at": "2022-01-16T14:42:00Z",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "finished_at": "2022-01-16T14:43:00Z",
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/compat-sessions/01FSHNCZP0PPF7X0EVMJNECPZW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHNCZP0PPF7X0EVMJNECPZW"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/compat-sessions?filter[status]=finished&page[first]=10",
            "first": "/api/admin/v1/compat-sessions?filter[status]=finished&page[first]=10",
            "last": "/api/admin/v1/compat-sessions?filter[status]=finished&page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/api/admin/v1/compat-sessions?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "compat-session",
              "id": "01FSHNB530AAPR7PEV8KNBZD5Y",
              "attributes": {
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "device_id": "LoieH5Iecx",
                "user_session_id": null,
                "redirect_uri": null,
                "created_at": "2022-01-16T14:41:00Z",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "finished_at": null,
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/compat-sessions/01FSHNB530AAPR7PEV8KNBZD5Y"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHNB530AAPR7PEV8KNBZD5Y"
                }
              }
            },
            {
              "type": "compat-session",
              "id": "01FSHNCZP0PPF7X0EVMJNECPZW",
              "attributes": {
                "user_id": "01FSHNB530AJ6AC5HQ9X6H4RP4",
                "device_id": "ZXyvelQWW9",
                "user_session_id": null,
                "redirect_uri": null,
                "created_at": "2022-01-16T14:42:00Z",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "finished_at": "2022-01-16T14:43:00Z",
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/compat-sessions/01FSHNCZP0PPF7X0EVMJNECPZW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHNCZP0PPF7X0EVMJNECPZW"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/compat-sessions?count=false&page[first]=10",
            "first": "/api/admin/v1/compat-sessions?count=false&page[first]=10",
            "last": "/api/admin/v1/compat-sessions?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/compat-sessions?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/api/admin/v1/compat-sessions?count=only"
          }
        }
        "#);

        // Test count=false with filtering
        let request = Request::get(format!(
            "/api/admin/v1/compat-sessions?count=false&filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "compat-session",
              "id": "01FSHNB530AAPR7PEV8KNBZD5Y",
              "attributes": {
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "device_id": "LoieH5Iecx",
                "user_session_id": null,
                "redirect_uri": null,
                "created_at": "2022-01-16T14:41:00Z",
                "user_agent": null,
                "last_active_at": null,
                "last_active_ip": null,
                "finished_at": null,
                "human_name": null
              },
              "links": {
                "self": "/api/admin/v1/compat-sessions/01FSHNB530AAPR7PEV8KNBZD5Y"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHNB530AAPR7PEV8KNBZD5Y"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/compat-sessions?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "first": "/api/admin/v1/compat-sessions?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "last": "/api/admin/v1/compat-sessions?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request =
            Request::get("/api/admin/v1/compat-sessions?count=only&filter[status]=active")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "links": {
            "self": "/api/admin/v1/compat-sessions?filter[status]=active&count=only"
          }
        }
        "#);
    }
}
