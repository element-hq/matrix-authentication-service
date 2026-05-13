// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashMap;

use mas_iana::oauth::{OAuthAccessTokenType, OAuthClientAuthenticationMethod};
use mas_oidc_client::requests::client_credentials::access_token_with_client_credentials;
use oauth2_types::{
    requests::AccessTokenResponse,
    scope::{PROFILE, Scope},
};
use rand::SeedableRng;
use wiremock::{
    Mock, Request, ResponseTemplate,
    matchers::{method, path},
};

use crate::{ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET, client_credentials, init_test, now};

#[tokio::test]
async fn pass_access_token_with_client_credentials() {
    let (http_client, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::ClientSecretPost, &issuer);
    let token_endpoint = issuer.join("token").unwrap();
    let scope = [PROFILE].into_iter().collect::<Scope>();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("grant_type")
                .filter(|s| *s == "client_credentials")
                .is_none()
            {
                println!("Wrong or missing grant type");
                return false;
            }
            if query_pairs
                .get("scope")
                .filter(|s| *s == "profile")
                .is_none()
            {
                println!("Wrong or missing scope");
                return false;
            }
            if query_pairs
                .get("client_id")
                .filter(|s| *s == CLIENT_ID)
                .is_none()
            {
                println!("Wrong or missing client ID");
                return false;
            }
            if query_pairs
                .get("client_secret")
                .filter(|s| *s == CLIENT_SECRET)
                .is_none()
            {
                println!("Wrong or missing client secret");
                return false;
            }

            true
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: None,
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: Some(scope.clone()),
            }),
        )
        .mount(&mock_server)
        .await;

    let response = access_token_with_client_credentials(
        &http_client,
        client_credentials,
        &token_endpoint,
        Some(scope),
        now(),
        &mut rng,
    )
    .await
    .unwrap();

    assert_eq!(response.access_token, ACCESS_TOKEN);
    assert_eq!(response.refresh_token, None);
    assert!(response.scope.unwrap().contains("profile"));
}
