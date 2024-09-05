// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::collections::HashMap;

use mas_iana::oauth::{OAuthClientAuthenticationMethod, OAuthTokenTypeHint};
use mas_oidc_client::{
    requests::introspection::introspect_token,
    types::scope::{ScopeExt, ScopeToken},
};
use oauth2_types::requests::IntrospectionResponse;
use rand::SeedableRng;
use wiremock::{
    matchers::{method, path},
    Mock, Request, ResponseTemplate,
};

use crate::{client_credentials, init_test, now, ACCESS_TOKEN, CLIENT_ID, SUBJECT_IDENTIFIER};

#[tokio::test]
async fn pass_introspect_token() {
    let (http_service, mock_server, issuer) = init_test().await;
    let client_credentials =
        client_credentials(&OAuthClientAuthenticationMethod::None, &issuer, None);
    let introspection_endpoint = issuer.join("introspect").unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    Mock::given(method("POST"))
        .and(path("/introspect"))
        .and(|req: &Request| {
            let query_pairs = form_urlencoded::parse(&req.body).collect::<HashMap<_, _>>();

            if query_pairs
                .get("token")
                .filter(|s| *s == ACCESS_TOKEN)
                .is_none()
            {
                println!("Wrong or missing token");
                return false;
            }
            if query_pairs
                .get("token_type_hint")
                .filter(|s| *s == "access_token")
                .is_none()
            {
                println!("Wrong or missing token type hint");
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
            ResponseTemplate::new(200).set_body_json(IntrospectionResponse {
                active: true,
                scope: Some([ScopeToken::Profile].into_iter().collect()),
                client_id: Some(CLIENT_ID.to_owned()),
                username: None,
                token_type: Some(OAuthTokenTypeHint::AccessToken),
                exp: None,
                iat: None,
                nbf: None,
                sub: Some(SUBJECT_IDENTIFIER.to_owned()),
                aud: Some(CLIENT_ID.to_owned()),
                iss: Some(issuer.to_string()),
                jti: None,
            }),
        )
        .mount(&mock_server)
        .await;

    let response = introspect_token(
        &http_service,
        client_credentials.into(),
        &introspection_endpoint,
        ACCESS_TOKEN.to_owned(),
        Some(OAuthTokenTypeHint::AccessToken),
        now(),
        &mut rng,
    )
    .await
    .unwrap();

    assert!(response.active);
    assert_eq!(response.aud.unwrap(), CLIENT_ID);
    assert!(response.scope.unwrap().contains_token(&ScopeToken::Profile));
    assert_eq!(response.client_id.unwrap(), CLIENT_ID);
    assert_eq!(response.iss.unwrap(), issuer.as_str());
    assert_eq!(response.sub.unwrap(), SUBJECT_IDENTIFIER);
}
