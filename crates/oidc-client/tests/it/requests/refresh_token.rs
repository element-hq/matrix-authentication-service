// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashMap;

use assert_matches::assert_matches;
use mas_iana::oauth::{OAuthAccessTokenType, OAuthClientAuthenticationMethod};
use mas_oidc_client::requests::refresh_token::refresh_access_token;
use oauth2_types::requests::AccessTokenResponse;
use rand::SeedableRng;
use wiremock::{
    Mock, Request, ResponseTemplate,
    matchers::{method, path},
};

use crate::{ACCESS_TOKEN, CLIENT_ID, REFRESH_TOKEN, client_credentials, init_test, now};

#[tokio::test]
async fn pass_refresh_access_token() {
    let (http_client, mock_server, issuer) = init_test().await;
    let client_credentials = client_credentials(&OAuthClientAuthenticationMethod::None, &issuer);
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("grant_type")
                .filter(|s| *s == "refresh_token")
                .is_none()
            {
                println!("Wrong or missing grant type");
                return false;
            }
            if query_pairs
                .get("refresh_token")
                .filter(|s| *s == REFRESH_TOKEN)
                .is_none()
            {
                println!("Wrong or missing refresh token");
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

            true
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(AccessTokenResponse {
                access_token: ACCESS_TOKEN.to_owned(),
                refresh_token: None,
                id_token: None,
                token_type: OAuthAccessTokenType::Bearer,
                expires_in: None,
                scope: None,
                issued_token_type: None,
            }),
        )
        .mount(&mock_server)
        .await;

    let (response, response_id_token) = refresh_access_token(
        &http_client,
        client_credentials,
        &token_endpoint,
        REFRESH_TOKEN.to_owned(),
        None,
        None,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();

    assert_eq!(response.access_token, ACCESS_TOKEN);
    assert_eq!(response.refresh_token, None);
    assert_matches!(response_id_token, None);
}
