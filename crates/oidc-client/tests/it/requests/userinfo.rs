// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use assert_matches::assert_matches;
use mas_oidc_client::{
    error::{IdTokenError, UserInfoError},
    requests::userinfo::fetch_userinfo,
};
use serde_json::json;
use wiremock::{
    matchers::{header, method, path},
    Mock, ResponseTemplate,
};

use crate::{id_token, init_test, ACCESS_TOKEN, SUBJECT_IDENTIFIER};

#[tokio::test]
async fn pass_fetch_userinfo() {
    let (http_client, mock_server, issuer) = init_test().await;
    let userinfo_endpoint = issuer.join("userinfo").unwrap();
    let (auth_id_token, _) = id_token(issuer.as_str());

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .and(header(
            "authorization",
            format!("Bearer {ACCESS_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sub": SUBJECT_IDENTIFIER,
            "email": "janedoe@example.com",
        })))
        .mount(&mock_server)
        .await;

    let claims = fetch_userinfo(
        &http_client,
        &userinfo_endpoint,
        ACCESS_TOKEN,
        None,
        &auth_id_token,
    )
    .await
    .unwrap();

    assert_eq!(claims.get("email").unwrap(), "janedoe@example.com");
}

#[tokio::test]
async fn fail_wrong_subject_identifier() {
    let (http_client, mock_server, issuer) = init_test().await;
    let userinfo_endpoint = issuer.join("userinfo").unwrap();
    let (auth_id_token, _) = id_token(issuer.as_str());

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .and(header(
            "authorization",
            format!("Bearer {ACCESS_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sub": "wrong_subject_identifier",
            "email": "janedoe@example.com",
        })))
        .mount(&mock_server)
        .await;

    let error = fetch_userinfo(
        &http_client,
        &userinfo_endpoint,
        ACCESS_TOKEN,
        None,
        &auth_id_token,
    )
    .await
    .unwrap_err();

    assert_matches!(
        error,
        UserInfoError::IdToken(IdTokenError::WrongSubjectIdentifier)
    );
}
