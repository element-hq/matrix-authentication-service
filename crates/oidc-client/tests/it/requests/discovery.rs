// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use assert_matches::assert_matches;
use mas_iana::oauth::{OAuthAuthorizationEndpointResponseType, PkceCodeChallengeMethod};
use mas_jose::jwa::SUPPORTED_SIGNING_ALGORITHMS;
use mas_oidc_client::{
    error::DiscoveryError,
    requests::discovery::{discover, insecure_discover},
};
use oauth2_types::oidc::{ProviderMetadata, SubjectType};
use url::Url;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use crate::init_test;

fn provider_metadata(issuer: &Url) -> ProviderMetadata {
    ProviderMetadata {
        issuer: Some(issuer.as_str().to_owned()),
        authorization_endpoint: issuer.join("authorize").ok(),
        token_endpoint: issuer.join("token").ok(),
        jwks_uri: issuer.join("jwks").ok(),
        response_types_supported: Some(vec![OAuthAuthorizationEndpointResponseType::Code.into()]),
        subject_types_supported: Some(vec![SubjectType::Pairwise, SubjectType::Public]),
        id_token_signing_alg_values_supported: Some(SUPPORTED_SIGNING_ALGORITHMS.into()),
        code_challenge_methods_supported: Some(vec![PkceCodeChallengeMethod::S256]),
        ..Default::default()
    }
}

#[tokio::test]
async fn pass_discover() {
    let (http_client, mock_server, issuer) = init_test().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(provider_metadata(&issuer)))
        .mount(&mock_server)
        .await;

    let provider_metadata = insecure_discover(&http_client, issuer.as_str())
        .await
        .unwrap();

    assert_eq!(provider_metadata.issuer(), issuer.as_str());
}

#[tokio::test]
async fn fail_discover_404() {
    let (http_client, _mock_server, issuer) = init_test().await;

    let error = discover(&http_client, issuer.as_str()).await.unwrap_err();

    assert_matches!(error, DiscoveryError::Http(_));
}

#[tokio::test]
async fn fail_discover_not_json() {
    let (http_client, mock_server, issuer) = init_test().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let error = discover(&http_client, issuer.as_str()).await.unwrap_err();

    assert_matches!(error, DiscoveryError::Http(_));
}

#[tokio::test]
async fn fail_discover_invalid_metadata() {
    let (http_client, mock_server, issuer) = init_test().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ProviderMetadata::default()))
        .mount(&mock_server)
        .await;

    let error = discover(&http_client, issuer.as_str()).await.unwrap_err();

    assert_matches!(error, DiscoveryError::Validation(_));
}
