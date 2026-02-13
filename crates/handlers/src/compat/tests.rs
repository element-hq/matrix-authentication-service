// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::http::{Request, StatusCode};
use mas_matrix::{HomeserverConnection, ProvisionRequest};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum LoginCredentials {
    #[serde(rename = "m.login.password")]
    Password {
        identifier: LoginIdentifier,
        password: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum LoginIdentifier {
    #[serde(rename = "m.id.user")]
    User { user: String },
}

#[derive(Debug, Serialize)]
struct LoginRequest {
    #[serde(flatten)]
    credentials: LoginCredentials,
    #[serde(default)]
    refresh_token: bool,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    #[allow(dead_code)]
    access_token: String,
    #[allow(dead_code)]
    user_id: String,
    #[allow(dead_code)]
    device_id: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    expires_in_ms: i64,
}

/// Test using a compatibility refresh token.
#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_compat_refresh(pool: sqlx::PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Create a user
    create_test_user(&state, "testuser").await;

    // Login to get initial tokens
    let login_request = Request::post("/_matrix/client/v3/login").json(&LoginRequest {
        credentials: LoginCredentials::Password {
            identifier: LoginIdentifier::User {
                user: "testuser".to_owned(),
            },
            password: "password".to_owned(),
        },
        refresh_token: true,
    });

    let login_response = state.request(login_request).await;
    login_response.assert_status(StatusCode::OK);

    let login_response: LoginResponse = login_response.json();
    let initial_refresh_token = login_response
        .refresh_token
        .expect("Login should return a refresh token");

    // First refresh
    let refresh_request = Request::post("/_matrix/client/v3/refresh").json(&RefreshRequest {
        refresh_token: initial_refresh_token.clone(),
    });

    let first_refresh_response = state.request(refresh_request).await;
    first_refresh_response.assert_status(StatusCode::OK);

    let first_refresh_response: RefreshResponse = first_refresh_response.json();
    let first_new_refresh_token = first_refresh_response.refresh_token.clone();

    assert_eq!(
        first_refresh_response,
        RefreshResponse {
            access_token: "mct_fNbm5KAQovodfVQz7IvDc44woP66fR_fsaiD1".to_owned(),
            refresh_token: "mcr_42oTpLoieH5IecxG6gZXyvelQWW9Xq_a8g5N3".to_owned(),
            expires_in_ms: 300_000
        }
    );

    // Use the token from the /refresh response to /refresh again,
    // proving that it works.
    // This is a regression test: we were previously consuming the refresh token
    // before it was returned from /refresh.
    let second_refresh_request =
        Request::post("/_matrix/client/v3/refresh").json(&RefreshRequest {
            refresh_token: first_new_refresh_token.clone(),
        });

    let second_refresh_response = state.request(second_refresh_request).await;
    second_refresh_response.assert_status(StatusCode::OK);

    let second_refresh_response: RefreshResponse = second_refresh_response.json();

    assert_eq!(
        second_refresh_response,
        RefreshResponse {
            access_token: "???".to_owned(),
            refresh_token: "???".to_owned(),
            expires_in_ms: 300_000
        }
    );
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_refresh_with_invalid_token(pool: sqlx::PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    let refresh_request = RefreshRequest {
        refresh_token: "invalid_token".to_owned(),
    };

    let refresh_request = Request::post("/_matrix/client/v3/refresh").json(&refresh_request);

    let response = state.request(refresh_request).await;
    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn test_refresh_with_consumed_token(pool: sqlx::PgPool) {
    setup();
    let state = TestState::from_pool(pool).await.unwrap();

    // Create a user and login
    create_test_user(&state, "testuser").await;

    let login_request = LoginRequest {
        credentials: LoginCredentials::Password {
            identifier: LoginIdentifier::User {
                user: "testuser".to_owned(),
            },
            password: "password".to_owned(),
        },
        refresh_token: true,
    };

    let login_request = Request::post("/_matrix/client/v3/login").json(&login_request);

    let login_response = state.request(login_request).await;
    login_response.assert_status(StatusCode::OK);

    let login_response: LoginResponse = login_response.json();
    let refresh_token = login_response
        .refresh_token
        .expect("Login should return a refresh token");

    let refresh_request = RefreshRequest {
        refresh_token: refresh_token.clone(),
    };

    // Use the refresh token once
    let first_refresh_request = Request::post("/_matrix/client/v3/refresh").json(&refresh_request);
    let first_refresh_response = state.request(first_refresh_request).await;
    first_refresh_response.assert_status(StatusCode::OK);

    let _first_refresh_response: RefreshResponse = first_refresh_response.json();

    // Try to use the same refresh token again - should fail because it's consumed
    let second_refresh_request =
        Request::post("/_matrix/client/v3/refresh").json(&refresh_request);

    let second_refresh_response = state.request(second_refresh_request).await;
    second_refresh_response.assert_status(StatusCode::UNAUTHORIZED);
}

async fn create_test_user(state: &TestState, username: &str) -> mas_data_model::User {
    let mut repo = state.repository().await.unwrap();
    let mut rng = state.rng();

    let user = repo
        .user()
        .add(&mut rng, &state.clock, username.to_owned())
        .await
        .unwrap();

    let password = Zeroizing::new("password".to_owned());
    let (version, hashed_password) = state
        .password_manager
        .hash(&mut rng, password)
        .await
        .unwrap();

    repo.user_password()
        .add(
            &mut rng,
            &state.clock,
            &user,
            version,
            hashed_password,
            None,
        )
        .await
        .unwrap();

    // Provision the user on the homeserver
    state
        .homeserver_connection
        .provision_user(&ProvisionRequest::new(&user.username, &user.sub))
        .await
        .unwrap();

    repo.save().await.unwrap();

    user
}
