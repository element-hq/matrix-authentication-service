// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use mas_oidc_client::requests::userinfo::fetch_userinfo;
use serde_json::json;
use wiremock::{
    matchers::{header, method, path},
    Mock, ResponseTemplate,
};

use crate::{init_test, ACCESS_TOKEN, SUBJECT_IDENTIFIER};

#[tokio::test]
async fn pass_fetch_userinfo() {
    let (http_client, mock_server, issuer) = init_test().await;
    let userinfo_endpoint = issuer.join("userinfo").unwrap();

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

    let claims = fetch_userinfo(&http_client, &userinfo_endpoint, ACCESS_TOKEN, None)
        .await
        .unwrap();

    assert_eq!(claims.get("email").unwrap(), "janedoe@example.com");
}
