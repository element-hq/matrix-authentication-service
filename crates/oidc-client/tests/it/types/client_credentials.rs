// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashMap;

use base64ct::Encoding;
use http::header::AUTHORIZATION;
use mas_iana::oauth::{OAuthAccessTokenType, OAuthClientAuthenticationMethod};
use mas_jose::{
    claims::{self, TimeOptions},
    jwt::Jwt,
};
use mas_oidc_client::{
    requests::client_credentials::access_token_with_client_credentials,
    types::client_credentials::ClientCredentials,
};
use oauth2_types::requests::AccessTokenResponse;
use rand::SeedableRng;
use serde_json::Value;
use wiremock::{
    Mock, Request, ResponseTemplate,
    matchers::{header, method, path},
};

use crate::{ACCESS_TOKEN, CLIENT_ID, CLIENT_SECRET, client_credentials, init_test, now};

#[tokio::test]
async fn pass_none() {
    let (http_client, mock_server, issuer) = init_test().await;
    let client_credentials = client_credentials(&OAuthClientAuthenticationMethod::None, &issuer);
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

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

    access_token_with_client_credentials(
        &http_client,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pass_client_secret_basic() {
    let (http_client, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::ClientSecretBasic, &issuer);
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let username = form_urlencoded::byte_serialize(CLIENT_ID.as_bytes()).collect::<String>();
    let password = form_urlencoded::byte_serialize(CLIENT_SECRET.as_bytes()).collect::<String>();
    let enc_user_pass =
        base64ct::Base64::encode_string(format!("{username}:{password}").as_bytes());
    let authorization_header = format!("Basic {enc_user_pass}");

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header(AUTHORIZATION, authorization_header.as_str()))
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

    access_token_with_client_credentials(
        &http_client,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pass_client_secret_post() {
    let (http_client, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::ClientSecretPost, &issuer);
    let token_endpoint = issuer.join("token").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

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
                scope: None,
                issued_token_type: None,
            }),
        )
        .mount(&mock_server)
        .await;

    access_token_with_client_credentials(
        &http_client,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pass_client_secret_jwt() {
    let (http_client, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::ClientSecretJwt, &issuer);
    let token_endpoint = issuer.join("token").unwrap();
    let endpoint = token_endpoint.to_string();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(move |req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs.contains_key("client_id") {
                println!("`client_secret_jwt` client authentication should not use `client_id`");
                return false;
            }
            if query_pairs
                .get("client_assertion_type")
                .filter(|s| *s == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .is_none()
            {
                println!("Wrong or missing client assertion type");
                return false;
            }

            let Some(jwt) = query_pairs.get("client_assertion") else {
                println!("Missing client assertion");
                return false;
            };

            let jwt = Jwt::<HashMap<String, Value>>::try_from(jwt.as_ref()).unwrap();
            if jwt
                .verify_with_shared_secret(CLIENT_SECRET.as_bytes().to_owned())
                .is_err()
            {
                println!("Client assertion signature verification failed");
                return false;
            }

            let mut claims = jwt.into_parts().1;
            if let Err(error) = verify_client_jwt(&mut claims, &endpoint) {
                println!("Client assertion claims verification failed: {error}");
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

    access_token_with_client_credentials(
        &http_client,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pass_private_key_jwt() {
    let (http_client, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::PrivateKeyJwt, &issuer);
    let token_endpoint = issuer.join("token").unwrap();
    let endpoint = token_endpoint.to_string();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let ClientCredentials::PrivateKeyJwt { keystore, .. } = &client_credentials else {
        panic!("should be PrivateKeyJwt")
    };
    let client_jwks = keystore.public_jwks();

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(move |req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs.contains_key("client_id") {
                println!("`private_key_jwt` client authentication should not use `client_id`");
                return false;
            }
            if query_pairs
                .get("client_assertion_type")
                .filter(|s| *s == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .is_none()
            {
                println!("Wrong or missing client assertion type");
                return false;
            }

            let Some(jwt) = query_pairs.get("client_assertion") else {
                println!("Missing client assertion");
                return false;
            };

            let jwt = Jwt::<HashMap<String, Value>>::try_from(jwt.as_ref()).unwrap();
            if jwt.verify_with_jwks(&client_jwks).is_err() {
                println!("Client assertion signature verification failed");
                return false;
            }

            let mut claims = jwt.into_parts().1;
            if let Err(error) = verify_client_jwt(&mut claims, &endpoint) {
                println!("Client assertion claims verification failed: {error}");
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

    access_token_with_client_credentials(
        &http_client,
        client_credentials,
        &token_endpoint,
        None,
        now(),
        &mut rng,
    )
    .await
    .unwrap();
}

fn verify_client_jwt(
    claims: &mut HashMap<String, Value>,
    token_endpoint: &String,
) -> Result<(), Box<dyn std::error::Error>> {
    claims::ISS.extract_required_with_options(claims, CLIENT_ID)?;

    let sub = claims::SUB.extract_required(claims)?;
    if sub != CLIENT_ID {
        return Err("Wrong sub".into());
    }

    claims::AUD.extract_required_with_options(claims, token_endpoint)?;

    claims::EXP.extract_required_with_options(claims, TimeOptions::new(now()))?;

    Ok(())
}
