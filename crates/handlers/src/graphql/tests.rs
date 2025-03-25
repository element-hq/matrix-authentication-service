// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::http::Request;
use hyper::StatusCode;
use mas_data_model::{AccessToken, Client, TokenType, User};
use mas_matrix::{HomeserverConnection, ProvisionRequest};
use mas_router::SimpleRoute;
use mas_storage::{
    RepositoryAccess,
    oauth2::{OAuth2AccessTokenRepository, OAuth2ClientRepository},
};
use oauth2_types::{
    registration::ClientRegistrationResponse,
    requests::AccessTokenResponse,
    scope::{OPENID, Scope, ScopeToken},
};
use sqlx::PgPool;

use crate::{
    test_utils,
    test_utils::{RequestBuilderExt, ResponseExt, TestState, setup},
};

async fn create_test_client(state: &TestState) -> Client {
    let mut repo = state.repository().await.unwrap();
    let mut rng = state.rng();

    let client = repo
        .oauth2_client()
        .add(
            &mut rng,
            &state.clock,
            vec![],
            None,
            None,
            None,
            vec![],
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

    repo.save().await.unwrap();

    client
}

async fn create_test_user<U: Into<String> + Send>(state: &TestState, username: U) -> User {
    let username = username.into();
    let mut repo = state.repository().await.unwrap();
    let mut rng = state.rng();

    let user = repo
        .user()
        .add(&mut rng, &state.clock, username)
        .await
        .unwrap();

    repo.save().await.unwrap();

    user
}

async fn start_oauth_session(
    state: &TestState,
    client: &Client,
    user: &User,
    scope: Scope,
) -> AccessToken {
    let mut repo = state.repository().await.unwrap();
    let mut rng = state.rng();

    let browser_session = repo
        .browser_session()
        .add(&mut rng, &state.clock, user, None)
        .await
        .unwrap();

    let session = repo
        .oauth2_session()
        .add_from_browser_session(&mut rng, &state.clock, client, &browser_session, scope)
        .await
        .unwrap();

    let access_token_str = TokenType::AccessToken.generate(&mut rng);

    let access_token = repo
        .oauth2_access_token()
        .add(&mut rng, &state.clock, &session, access_token_str, None)
        .await
        .unwrap();

    repo.save().await.unwrap();

    access_token
}

const GRAPHQL: ScopeToken = ScopeToken::from_static("urn:mas:graphql:*");
const ADMIN: ScopeToken = ScopeToken::from_static("urn:mas:admin");

#[derive(serde::Deserialize)]
struct GraphQLResponse {
    #[serde(default)]
    data: serde_json::Value,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

/// Test that the GraphQL endpoint can be queried with a GET request.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_get(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    let request = Request::get("/graphql?query={viewer{__typename}}").empty();

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "viewer": {
                "__typename": "Anonymous",
            },
        })
    );
}

/// Test that the GraphQL endpoint can be queried with a POST request
/// anonymously.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_anonymous_viewer(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    let req = Request::post("/graphql").json(serde_json::json!({
        "query": r"
            query {
                viewer {
                    __typename
                }
            }
        ",
    }));

    let response = state.request(req).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "viewer": {
                "__typename": "Anonymous",
            },
        })
    );
}

/// Test that the GraphQL endpoint can be authenticated with a bearer token.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_oauth2_viewer(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Start by creating a user, a client and a token
    let client = create_test_client(&state).await;
    let user = create_test_user(&state, "alice").await;
    let access_token =
        start_oauth_session(&state, &client, &user, Scope::from_iter([GRAPHQL])).await;
    let access_token = access_token.access_token;

    let req = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r"
                query {
                    viewer {
                        __typename

                        ... on User {
                            id
                            username
                        }
                    }
                }
            ",
        }));

    let response = state.request(req).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "viewer": {
                "__typename": "User",
                "id": format!("user:{id}", id = user.id),
                "username": "alice",
            },
        })
    );
}

/// Test that the GraphQL endpoint requires the GraphQL scope.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_oauth2_no_scope(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Start by creating a user, a client and a token
    let client = create_test_client(&state).await;
    let user = create_test_user(&state, "alice").await;
    let access_token =
        start_oauth_session(&state, &client, &user, Scope::from_iter([OPENID])).await;
    let access_token = access_token.access_token;

    let req = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r"
                query {
                    viewer {
                        __typename
                    }
                }
            ",
        }));

    let response = state.request(req).await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let response: GraphQLResponse = response.json();

    assert_eq!(
        response.errors,
        vec![serde_json::json!({
            "message": "Missing urn:mas:graphql:* scope",
        })]
    );
    assert_eq!(response.data, serde_json::json!(null));
}

/// Test the admin scope on the GraphQL endpoint.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_oauth2_admin(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Start by creating a user, a client and two tokens
    let client = create_test_client(&state).await;
    let user = create_test_user(&state, "alice").await;

    // Regular access token
    let access_token =
        start_oauth_session(&state, &client, &user, Scope::from_iter([GRAPHQL])).await;
    let access_token = access_token.access_token;

    // Admin access token
    let access_token_admin =
        start_oauth_session(&state, &client, &user, Scope::from_iter([GRAPHQL, ADMIN])).await;
    let access_token_admin = access_token_admin.access_token;

    // Create a second user and try to query stuff about it
    let user2 = create_test_user(&state, "bob").await;

    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r"
                query UserQuery($id: ID) {
                    user(id: $id) {
                        id
                        username
                    }
                }
            ",
            "variables": {
                "id": format!("user:{id}", id = user2.id),
            },
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    // It should not find the user, because it's not the owner and not an admin
    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "user": null,
        })
    );

    // Do the same request with the admin token
    let request = Request::post("/graphql")
        .bearer(&access_token_admin)
        .json(serde_json::json!({
            "query": r"
                query UserQuery($id: ID) {
                    user(id: $id) {
                        id
                        username
                    }
                }
            ",
            "variables": {
                "id": format!("user:{id}", id = user2.id),
            },
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();

    // It should find the user, because the token has the admin scope
    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "user": {
                "id": format!("user:{id}", id = user2.id),
                "username": "bob",
            },
        })
    );
}

/// Test that we can query the GraphQL endpoint with a token from a
/// client_credentials grant.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_oauth2_client_credentials(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Provision a client
    let request =
        Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
            "client_uri": "https://example.com/",
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["client_credentials"],
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::CREATED);

    let response: ClientRegistrationResponse = response.json();
    let client_id = response.client_id;
    let client_secret = response.client_secret.expect("to have a client secret");

    // Call the token endpoint with the graphql scope
    let request = Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "urn:mas:graphql:*",
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let AccessTokenResponse { access_token, .. } = response.json();

    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r"
                query {
                    viewer {
                        __typename
                    }

                    viewerSession {
                        __typename
                    }
                }
            ",
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();
    assert!(response.errors.is_empty());
    assert_eq!(
        response.data,
        serde_json::json!({
            "viewer": {
                // There is no user associated with the client credentials grant
                "__typename": "Anonymous",
            },
            "viewerSession": {
                // But there is a session
                "__typename": "Oauth2Session",
            },
        })
    );

    // We shouldn't be able to call the addUser mutation
    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                mutation {
                    addUser(input: {username: "alice"}) {
                        user {
                            id
                            username
                        }
                    }
                }
            "#,
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();
    // There should be an error
    assert_eq!(response.errors.len(), 1);
    assert!(response.data.is_null());

    // Check that we can't do a query once the token is revoked
    let request = Request::post(mas_router::OAuth2Revocation::PATH).form(serde_json::json!({
        "token": access_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);

    // Do the same request again
    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r"
                query {
                    viewer {
                        __typename
                    }

                    viewerSession {
                        __typename
                    }
                }
            ",
        }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::UNAUTHORIZED);

    // Now make the client admin and try again
    let state = {
        let mut state = state;
        state.policy_factory = test_utils::policy_factory(
            "example.com",
            serde_json::json!({
                "admin_clients": [client_id],
            }),
        )
        .await
        .unwrap();
        state
    };

    // Ask for a token again, with the admin scope
    let request = Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "urn:mas:graphql:* urn:mas:admin",
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let AccessTokenResponse { access_token, .. } = response.json();

    // We should now be able to call the addUser mutation
    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                mutation {
                    addUser(input: {username: "alice"}) {
                        user {
                            id
                            username
                        }
                    }
                }
            "#,
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let user_id = response.data["addUser"]["user"]["id"].as_str().unwrap();

    assert_eq!(
        response.data,
        serde_json::json!({
            "addUser": {
                "user": {
                    "id": user_id,
                    "username": "alice"
                }
            }
        })
    );

    // XXX: we don't run the task worker here, so even though the addUser mutation
    // should have scheduled a job to provision the user, it won't run in the test,
    // so we need to do it manually
    let mxid = state.homeserver_connection.mxid("alice");
    state
        .homeserver_connection
        .provision_user(&ProvisionRequest::new(mxid, user_id))
        .await
        .unwrap();

    // We should now be able to create an arbitrary access token for the user
    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r"
                mutation CreateSession($userId: String!, $scope: String!) {
                    createOauth2Session(input: {userId: $userId, permanent: true, scope: $scope}) {
                        accessToken
                        refreshToken
                    }
                }
            ",
            "variables": {
                "userId": user_id,
                "scope": "urn:matrix:org.matrix.msc2967.client:device:AABBCCDDEE urn:matrix:org.matrix.msc2967.client:api:* urn:synapse:admin:*"
            },
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert!(response.data["createOauth2Session"]["refreshToken"].is_null());
    assert!(response.data["createOauth2Session"]["accessToken"].is_string());

    let token = response.data["createOauth2Session"]["accessToken"]
        .as_str()
        .unwrap();

    // We should find this token in the database
    let mut repo = state.repository().await.unwrap();
    let token = repo
        .oauth2_access_token()
        .find_by_token(token)
        .await
        .unwrap();
    assert!(token.is_some());
}

/// Test the addUser mutation
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_add_user(pool: PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Provision a client
    let request =
        Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
            "client_uri": "https://example.com/",
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["client_credentials"],
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::CREATED);

    let response: ClientRegistrationResponse = response.json();
    let client_id = response.client_id;
    let client_secret = response.client_secret.expect("to have a client secret");

    // Make the client admin
    let state = {
        let mut state = state;
        state.policy_factory = test_utils::policy_factory(
            "example.com",
            serde_json::json!({
                "admin_clients": [client_id],
            }),
        )
        .await
        .unwrap();
        state
    };

    // Ask for a token with the admin scope
    let request = Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "urn:mas:graphql:* urn:mas:admin",
    }));

    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let AccessTokenResponse { access_token, .. } = response.json();

    // We should now be able to call the addUser mutation
    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                mutation {
                    addUser(input: {username: "alice"}) {
                        status
                        user {
                            id
                            username
                        }
                    }
                }
            "#,
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let user_id = &response.data["addUser"]["user"]["id"];

    assert_eq!(
        response.data,
        serde_json::json!({
            "addUser": {
                "status": "ADDED",
                "user": {
                    "id": user_id,
                    "username": "alice"
                }
            }
        })
    );

    // If we add again, it should return the user with a status of "EXISTS"
    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                mutation {
                    addUser(input: {username: "alice"}) {
                        status
                        user {
                            id
                            username
                        }
                    }
                }
            "#,
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();
    assert!(response.errors.is_empty(), "{:?}", response.errors);

    assert_eq!(
        response.data,
        serde_json::json!({
            "addUser": {
                "status": "EXISTS",
                "user": {
                    "id": user_id,
                    "username": "alice"
                }
            }
        })
    );

    // Reserve a username on the homeserver and try to add it
    state.homeserver_connection.reserve_localpart("bob").await;
    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                mutation {
                    addUser(input: {username: "bob"}) {
                        status
                        user {
                            username
                        }
                    }
                }
            "#,
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();
    assert!(response.errors.is_empty(), "{:?}", response.errors);

    assert_eq!(
        response.data,
        serde_json::json!({
            "addUser": {
                "status": "RESERVED",
                "user": null,
            }
        })
    );

    // But we can force it with the skipHomeserverCheck flag
    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                mutation {
                    addUser(input: {username: "bob", skipHomeserverCheck: true}) {
                        status
                        user {
                            username
                        }
                    }
                }
            "#,
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();
    assert!(response.errors.is_empty(), "{:?}", response.errors);

    assert_eq!(
        response.data,
        serde_json::json!({
            "addUser": {
                "status": "ADDED",
                "user": {
                    "username": "bob",
                },
            }
        })
    );

    // This mutation shouldn't accept an invalid username
    let request = Request::post("/graphql")
        .bearer(&access_token)
        .json(serde_json::json!({
            "query": r#"
                mutation {
                    addUser(input: {username: "this is invalid"}) {
                        status
                        user {
                            username
                        }
                    }
                }
            "#,
        }));
    let response = state.request(request).await;
    response.assert_status(StatusCode::OK);
    let response: GraphQLResponse = response.json();
    assert!(response.errors.is_empty(), "{:?}", response.errors);

    assert_eq!(
        response.data,
        serde_json::json!({
            "addUser": {
                "status": "INVALID",
                "user": null,
            }
        })
    );
}
