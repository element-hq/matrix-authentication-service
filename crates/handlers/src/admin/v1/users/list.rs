// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{OperationIo, transform::TransformOperation};
use axum::{Json, response::IntoResponse};
use axum_extra::extract::{Query, QueryRejection};
use axum_macros::FromRequestParts;
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_storage::{Page, user::UserFilter};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    admin::{
        call_context::CallContext,
        model::{Resource, User},
        params::{IncludeCount, Pagination},
        response::{ErrorResponse, PaginatedResponse},
    },
    impl_from_error_for_route,
};

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum UserStatus {
    Active,
    Locked,
    Deactivated,
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Locked => write!(f, "locked"),
            Self::Deactivated => write!(f, "deactivated"),
        }
    }
}

#[derive(FromRequestParts, Deserialize, JsonSchema, OperationIo)]
#[serde(rename = "UserFilter")]
#[aide(input_with = "Query<FilterParams>")]
#[from_request(via(Query), rejection(RouteError))]
pub struct FilterParams {
    /// Retrieve users with (or without) the `admin` flag set
    #[serde(rename = "filter[admin]")]
    admin: Option<bool>,

    /// Retrieve users with (or without) the `legacy_guest` flag set
    #[serde(rename = "filter[legacy-guest]")]
    legacy_guest: Option<bool>,

    /// Retrieve users where the username matches contains the given string
    ///
    /// Note that this doesn't change the ordering of the result, which are
    /// still ordered by ID.
    #[serde(rename = "filter[search]")]
    search: Option<String>,

    /// Retrieve the items with the given status
    ///
    /// Defaults to retrieve all users, including locked ones.
    ///
    /// * `active`: Only retrieve active users
    ///
    /// * `locked`: Only retrieve locked users (includes deactivated users)
    ///
    /// * `deactivated`: Only retrieve deactivated users
    #[serde(rename = "filter[status]")]
    status: Option<UserStatus>,

    /// Retrieve users which have at least one active OAuth 2.0 session
    /// belonging to any of the given client IDs.
    ///
    /// This filter may be repeated; the semantics are OR across the supplied
    /// clients (a user matches if they have an active session for *any* of
    /// them).
    #[serde(default, rename = "filter[active-oauth2-client]")]
    #[schemars(with = "Vec<crate::admin::schema::Ulid>")]
    active_oauth2_client: Vec<Ulid>,

    /// Retrieve users which have (or don't have) at least one active
    /// (non-finished) OAuth 2.0 session, regardless of the client.
    #[serde(rename = "filter[has-active-oauth2-session]")]
    has_active_oauth2_session: Option<bool>,

    /// Retrieve users which have (or don't have) at least one active
    /// (non-finished) compatibility session.
    #[serde(rename = "filter[has-active-compat-session]")]
    has_active_compat_session: Option<bool>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(admin) = self.admin {
            write!(f, "{sep}filter[admin]={admin}")?;
            sep = '&';
        }
        if let Some(legacy_guest) = self.legacy_guest {
            write!(f, "{sep}filter[legacy-guest]={legacy_guest}")?;
            sep = '&';
        }
        if let Some(search) = &self.search {
            write!(f, "{sep}filter[search]={search}")?;
            sep = '&';
        }
        if let Some(status) = self.status {
            write!(f, "{sep}filter[status]={status}")?;
            sep = '&';
        }
        for client in &self.active_oauth2_client {
            write!(f, "{sep}filter[active-oauth2-client]={client}")?;
            sep = '&';
        }
        if let Some(has) = self.has_active_oauth2_session {
            write!(f, "{sep}filter[has-active-oauth2-session]={has}")?;
            sep = '&';
        }
        if let Some(has) = self.has_active_compat_session {
            write!(f, "{sep}filter[has-active-compat-session]={has}")?;
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

    #[error("Client ID {0} not found")]
    ClientNotFound(Ulid),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidFilter(_) => StatusCode::BAD_REQUEST,
            Self::ClientNotFound(_) => StatusCode::NOT_FOUND,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("listUsers")
        .summary("List users")
        .tag("user")
        .response_with::<200, Json<PaginatedResponse<User>>, _>(|t| {
            let users = User::samples();
            let pagination = mas_storage::Pagination::first(users.len());
            let page = Page {
                edges: users
                    .into_iter()
                    .map(|node| mas_storage::pagination::Edge {
                        cursor: node.id(),
                        node,
                    })
                    .collect(),
                has_next_page: true,
                has_previous_page: false,
            };

            t.description("Paginated response of users")
                .example(PaginatedResponse::for_page(
                    page,
                    pagination,
                    Some(42),
                    User::PATH,
                ))
        })
        .response_with::<404, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::ClientNotFound(Ulid::nil()));
            t.description("Client was not found").example(response)
        })
}

#[tracing::instrument(name = "handler.admin.v1.users.list", skip_all)]
pub async fn handler(
    CallContext { mut repo, .. }: CallContext,
    Pagination(pagination, include_count): Pagination,
    params: FilterParams,
) -> Result<Json<PaginatedResponse<User>>, RouteError> {
    let base = format!("{path}{params}", path = User::PATH);
    let base = include_count.add_to_base(&base);
    let filter = UserFilter::default();

    let filter = match params.admin {
        Some(true) => filter.can_request_admin_only(),
        Some(false) => filter.cannot_request_admin_only(),
        None => filter,
    };

    let filter = match params.legacy_guest {
        Some(true) => filter.guest_only(),
        Some(false) => filter.non_guest_only(),
        None => filter,
    };

    let filter = match params.search.as_deref() {
        Some(search) => filter.matching_search(search),
        None => filter,
    };

    let filter = match params.status {
        Some(UserStatus::Active) => filter.active_only(),
        Some(UserStatus::Locked) => filter.locked_only(),
        Some(UserStatus::Deactivated) => filter.deactivated_only(),
        None => filter,
    };

    // Validate every client ID before applying the filter, so that a
    // mistyped/non-existent client ID produces a 404 rather than silently
    // matching no users.
    for client_id in &params.active_oauth2_client {
        if repo.oauth2_client().lookup(*client_id).await?.is_none() {
            return Err(RouteError::ClientNotFound(*client_id));
        }
    }

    let filter = if params.active_oauth2_client.is_empty() {
        filter
    } else {
        filter.with_active_oauth2_session_for_any_of_clients(&params.active_oauth2_client)
    };

    let filter = match params.has_active_oauth2_session {
        Some(has) => filter.with_active_oauth2_session(has),
        None => filter,
    };

    let filter = match params.has_active_compat_session {
        Some(has) => filter.with_active_compat_session(has),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo.user().list(filter, pagination).await?;
            let count = repo.user().count(filter).await?;
            PaginatedResponse::for_page(page.map(User::from), pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo.user().list(filter, pagination).await?;
            PaginatedResponse::for_page(page.map(User::from), pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.user().count(filter).await?;
            PaginatedResponse::for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_data_model::Device;
    use mas_storage::{
        RepositoryAccess,
        compat::CompatSessionRepository,
        oauth2::{OAuth2ClientRepository, OAuth2SessionRepository},
    };
    use oauth2_types::{
        requests::GrantType,
        scope::{OPENID, Scope},
    };
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list_users(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        // Provision two users
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Test default behavior (count=true)
        let request = Request::get("/api/admin/v1/users").bearer(&token).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "attributes": {
                "username": "bob",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AJ6AC5HQ9X6H4RP4"
                }
              }
            },
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/users?page[first]=10",
            "first": "/api/admin/v1/users?page[first]=10",
            "last": "/api/admin/v1/users?page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/api/admin/v1/users?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "attributes": {
                "username": "bob",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0AJ6AC5HQ9X6H4RP4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AJ6AC5HQ9X6H4RP4"
                }
              }
            },
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/users?count=false&page[first]=10",
            "first": "/api/admin/v1/users?count=false&page[first]=10",
            "last": "/api/admin/v1/users?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/api/admin/v1/users?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/api/admin/v1/users?count=only"
          }
        }
        "###);

        // Test count=false with filtering
        let request = Request::get("/api/admin/v1/users?count=false&filter[search]=alice")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        insta::assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "user",
              "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "attributes": {
                "username": "alice",
                "created_at": "2022-01-16T14:40:00Z",
                "locked_at": null,
                "deactivated_at": null,
                "admin": false,
                "legacy_guest": false
              },
              "links": {
                "self": "/api/admin/v1/users/01FSHN9AG0MZAA6S4AF7CTV32E"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0MZAA6S4AF7CTV32E"
                }
              }
            }
          ],
          "links": {
            "self": "/api/admin/v1/users?filter[search]=alice&count=false&page[first]=10",
            "first": "/api/admin/v1/users?filter[search]=alice&count=false&page[first]=10",
            "last": "/api/admin/v1/users?filter[search]=alice&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get("/api/admin/v1/users?count=only&filter[search]=alice")
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
            "self": "/api/admin/v1/users?filter[search]=alice&count=only"
          }
        }
        "#);
    }

    /// Test the `filter[active-oauth2-client]` repeatable filter.
    ///
    /// Sets up two users with active `OAuth2` sessions on two distinct
    /// clients (plus a third user with no session). Filtering on *both*
    /// clients should return both users.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list_users_filter_active_oauth2_client(pool: PgPool) {
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
        let alice_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &alice, None)
            .await
            .unwrap();

        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();
        let bob_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &bob, None)
            .await
            .unwrap();

        // Carol exists but has no session — she should never be returned.
        repo.user()
            .add(&mut rng, &state.clock, "carol".to_owned())
            .await
            .unwrap();

        let make_client = async |repo: &mut mas_storage::BoxRepository,
                                 rng: &mut rand_chacha::ChaChaRng,
                                 host: &str| {
            repo.oauth2_client()
                .add(
                    rng,
                    &state.clock,
                    vec![format!("https://{host}/redirect").parse().unwrap()],
                    None,
                    None,
                    None,
                    vec![GrantType::AuthorizationCode],
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
                    None,
                )
                .await
                .unwrap()
        };

        let client_x = make_client(&mut repo, &mut rng, "x.example.com").await;
        let client_y = make_client(&mut repo, &mut rng, "y.example.com").await;

        // Alice has an active session for client_x
        repo.oauth2_session()
            .add_from_browser_session(
                &mut rng,
                &state.clock,
                &client_x,
                &alice_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();

        // Bob has an active session for client_y
        repo.oauth2_session()
            .add_from_browser_session(
                &mut rng,
                &state.clock,
                &client_y,
                &bob_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        // Filter on both clients: should return alice and bob (but not carol)
        let request = Request::get(format!(
            "/api/admin/v1/users?count=only&filter[active-oauth2-client]={x}&filter[active-oauth2-client]={y}",
            x = client_x.id,
            y = client_y.id,
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 2);

        // Filter on client_x only: just alice
        let request = Request::get(format!(
            "/api/admin/v1/users?count=only&filter[active-oauth2-client]={x}",
            x = client_x.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 1);

        // An unknown client ID -> 404
        let unknown = Ulid::nil();
        let request = Request::get(format!(
            "/api/admin/v1/users?filter[active-oauth2-client]={unknown}"
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    /// Test the `filter[has-active-compat-session]` filter in both
    /// directions.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list_users_filter_has_active_compat_session(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();

        // Alice has an active compat session.
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let device = Device::generate(&mut rng);
        repo.compat_session()
            .add(&mut rng, &state.clock, &alice, device, None, false, None)
            .await
            .unwrap();

        // Bob has a finished compat session.
        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();
        let device = Device::generate(&mut rng);
        let bob_session = repo
            .compat_session()
            .add(&mut rng, &state.clock, &bob, device, None, false, None)
            .await
            .unwrap();
        repo.compat_session()
            .finish(&state.clock, bob_session)
            .await
            .unwrap();

        // Carol has no compat session.
        repo.user()
            .add(&mut rng, &state.clock, "carol".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        // has-active-compat-session=true -> 1 (alice)
        let request =
            Request::get("/api/admin/v1/users?count=only&filter[has-active-compat-session]=true")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 1);

        // has-active-compat-session=false -> 2 (bob + carol). The admin
        // token is created via client-credentials and does not provision a
        // user.
        let request =
            Request::get("/api/admin/v1/users?count=only&filter[has-active-compat-session]=false")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 2);
    }

    /// Test the `filter[has-active-oauth2-session]` filter in both directions.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_list_users_filter_has_active_oauth2_session(pool: PgPool) {
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
                vec![GrantType::AuthorizationCode],
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
                None,
            )
            .await
            .unwrap();

        // Alice has an active OAuth2 session.
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let alice_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &alice, None)
            .await
            .unwrap();
        repo.oauth2_session()
            .add_from_browser_session(
                &mut rng,
                &state.clock,
                &client,
                &alice_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();

        // Bob has a finished OAuth2 session.
        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();
        let bob_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &bob, None)
            .await
            .unwrap();
        let bob_oauth2 = repo
            .oauth2_session()
            .add_from_browser_session(
                &mut rng,
                &state.clock,
                &client,
                &bob_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.oauth2_session()
            .finish(&state.clock, bob_oauth2)
            .await
            .unwrap();

        // Carol has no OAuth2 session.
        repo.user()
            .add(&mut rng, &state.clock, "carol".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        // has-active-oauth2-session=true -> 1 (alice)
        let request =
            Request::get("/api/admin/v1/users?count=only&filter[has-active-oauth2-session]=true")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 1);

        // has-active-oauth2-session=false -> 2 (bob + carol). The admin token
        // is created via client-credentials and does not provision a user.
        let request =
            Request::get("/api/admin/v1/users?count=only&filter[has-active-oauth2-session]=false")
                .bearer(&token)
                .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["meta"]["count"], 2);
    }
}
