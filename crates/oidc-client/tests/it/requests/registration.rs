// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use assert_matches::assert_matches;
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_jose::jwk::PublicJsonWebKeySet;
use mas_oidc_client::{error::RegistrationError, requests::registration::register_client};
use oauth2_types::{
    oidc::ApplicationType,
    registration::{ClientMetadata, ClientRegistrationResponse, VerifiedClientMetadata},
};
use serde_json::json;
use url::Url;
use wiremock::{
    matchers::{body_partial_json, method, path},
    Mock, Request, ResponseTemplate,
};

use crate::{init_test, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI};

/// Generate valid client metadata for the given authentication method.
fn client_metadata(auth_method: OAuthClientAuthenticationMethod) -> VerifiedClientMetadata {
    let (signing_alg, jwks) = match &auth_method {
        OAuthClientAuthenticationMethod::ClientSecretJwt => {
            (Some(JsonWebSignatureAlg::Hs256), None)
        }
        OAuthClientAuthenticationMethod::PrivateKeyJwt => (
            Some(JsonWebSignatureAlg::Es256),
            Some(PublicJsonWebKeySet::default()),
        ),
        _ => (None, None),
    };

    ClientMetadata {
        redirect_uris: Some(vec![Url::parse(REDIRECT_URI).expect("Couldn't parse URL")]),
        application_type: Some(ApplicationType::Native),
        token_endpoint_auth_method: Some(auth_method),
        token_endpoint_auth_signing_alg: signing_alg,
        jwks,
        ..Default::default()
    }
    .validate()
    .unwrap()
}

#[tokio::test]
async fn pass_register_client_none() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_metadata = client_metadata(OAuthClientAuthenticationMethod::None);
    let registration_endpoint = issuer.join("register").unwrap();

    Mock::given(method("POST"))
        .and(path("/register"))
        .and(body_partial_json(json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ClientRegistrationResponse {
                client_id: CLIENT_ID.to_owned(),
                client_secret: None,
                client_id_issued_at: None,
                client_secret_expires_at: None,
            }),
        )
        .mount(&mock_server)
        .await;

    let response = register_client(&http_service, &registration_endpoint, client_metadata, None)
        .await
        .unwrap();

    assert_eq!(response.client_id, CLIENT_ID);
    assert_eq!(response.client_secret, None);
}

#[tokio::test]
async fn pass_register_client_client_secret_basic() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_metadata = client_metadata(OAuthClientAuthenticationMethod::ClientSecretBasic);
    let registration_endpoint = issuer.join("register").unwrap();

    Mock::given(method("POST"))
        .and(path("/register"))
        .and(body_partial_json(json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "client_secret_basic",
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ClientRegistrationResponse {
                client_id: CLIENT_ID.to_owned(),
                client_secret: Some(CLIENT_SECRET.to_owned()),
                client_id_issued_at: None,
                client_secret_expires_at: None,
            }),
        )
        .mount(&mock_server)
        .await;

    let response = register_client(&http_service, &registration_endpoint, client_metadata, None)
        .await
        .unwrap();

    assert_eq!(response.client_id, CLIENT_ID);
    assert_eq!(response.client_secret.unwrap(), CLIENT_SECRET);
}

#[tokio::test]
async fn pass_register_client_client_secret_post() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_metadata = client_metadata(OAuthClientAuthenticationMethod::ClientSecretPost);
    let registration_endpoint = issuer.join("register").unwrap();

    Mock::given(method("POST"))
        .and(path("/register"))
        .and(body_partial_json(json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "client_secret_post",
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ClientRegistrationResponse {
                client_id: CLIENT_ID.to_owned(),
                client_secret: Some(CLIENT_SECRET.to_owned()),
                client_id_issued_at: None,
                client_secret_expires_at: None,
            }),
        )
        .mount(&mock_server)
        .await;

    let response = register_client(&http_service, &registration_endpoint, client_metadata, None)
        .await
        .unwrap();

    assert_eq!(response.client_id, CLIENT_ID);
    assert_eq!(response.client_secret.unwrap(), CLIENT_SECRET);
}

#[tokio::test]
async fn pass_register_client_client_secret_jwt() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_metadata = client_metadata(OAuthClientAuthenticationMethod::ClientSecretJwt);
    let registration_endpoint = issuer.join("register").unwrap();

    Mock::given(method("POST"))
        .and(path("/register"))
        .and(body_partial_json(json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "client_secret_jwt",
            "token_endpoint_auth_signing_alg": "HS256",
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ClientRegistrationResponse {
                client_id: CLIENT_ID.to_owned(),
                client_secret: Some(CLIENT_SECRET.to_owned()),
                client_id_issued_at: None,
                client_secret_expires_at: None,
            }),
        )
        .mount(&mock_server)
        .await;

    let response = register_client(&http_service, &registration_endpoint, client_metadata, None)
        .await
        .unwrap();

    assert_eq!(response.client_id, CLIENT_ID);
    assert_eq!(response.client_secret.unwrap(), CLIENT_SECRET);
}

#[tokio::test]
async fn pass_register_client_private_key_jwt() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_metadata = client_metadata(OAuthClientAuthenticationMethod::PrivateKeyJwt);
    let registration_endpoint = issuer.join("register").unwrap();

    Mock::given(method("POST"))
        .and(path("/register"))
        .and(|req: &Request| {
            let Ok(metadata) = req.body_json::<ClientMetadata>() else {
                return false;
            };

            *metadata.token_endpoint_auth_method() == OAuthClientAuthenticationMethod::PrivateKeyJwt
                && metadata.token_endpoint_auth_signing_alg == Some(JsonWebSignatureAlg::Es256)
                && metadata.jwks.is_some()
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ClientRegistrationResponse {
                client_id: CLIENT_ID.to_owned(),
                client_secret: None,
                client_id_issued_at: None,
                client_secret_expires_at: None,
            }),
        )
        .mount(&mock_server)
        .await;

    let response = register_client(&http_service, &registration_endpoint, client_metadata, None)
        .await
        .unwrap();

    assert_eq!(response.client_id, CLIENT_ID);
    assert_eq!(response.client_secret, None);
}

#[tokio::test]
async fn fail_register_client_404() {
    let (http_service, _, issuer) = init_test().await;
    let client_metadata = client_metadata(OAuthClientAuthenticationMethod::None);
    let registration_endpoint = issuer.join("register").unwrap();

    let error = register_client(&http_service, &registration_endpoint, client_metadata, None)
        .await
        .unwrap_err();

    assert_matches!(error, RegistrationError::Http(_));
}

#[tokio::test]
async fn fail_register_client_missing_secret() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_metadata = client_metadata(OAuthClientAuthenticationMethod::ClientSecretBasic);
    let registration_endpoint = issuer.join("register").unwrap();

    Mock::given(method("POST"))
        .and(path("/register"))
        .and(body_partial_json(json!({
            "token_endpoint_auth_method": "client_secret_basic",
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(ClientRegistrationResponse {
                client_id: CLIENT_ID.to_owned(),
                client_secret: None,
                client_id_issued_at: None,
                client_secret_expires_at: None,
            }),
        )
        .mount(&mock_server)
        .await;

    let error = register_client(&http_service, &registration_endpoint, client_metadata, None)
        .await
        .unwrap_err();

    assert_matches!(error, RegistrationError::MissingClientSecret);
}
