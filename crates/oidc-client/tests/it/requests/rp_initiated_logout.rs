// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::collections::HashMap;

use assert_matches::assert_matches;
use mas_oidc_client::requests::rp_initiated_logout::{build_end_session_url, LogoutData};
use rand::SeedableRng;
use url::Url;

#[test]
fn build_url_no_redirect() {
    let end_session_endpoint = Url::parse("https://localhost/end_session").unwrap();
    let logout_data = LogoutData {
        id_token_hint: Some("fake.id.token".to_owned()),
        ui_locales: Some(vec!["pt-BR".parse().unwrap(), "pt".parse().unwrap()]),
        ..Default::default()
    };
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let (url, state) = build_end_session_url(end_session_endpoint, logout_data, &mut rng).unwrap();

    assert_eq!(url.path(), "/end_session");
    assert_eq!(state, None);

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.get("id_token_hint").unwrap(), "fake.id.token");
    assert_eq!(query_pairs.get("logout_hint"), None);
    assert_eq!(query_pairs.get("client_id"), None);
    assert_eq!(query_pairs.get("post_logout_redirect_uri"), None);
    assert_eq!(query_pairs.get("ui_locales").unwrap(), "pt-BR pt");
    assert_eq!(query_pairs.get("state"), None);
}

#[test]
fn build_url_with_redirect() {
    let end_session_endpoint = Url::parse("https://localhost/end_session").unwrap();
    let logout_data = LogoutData {
        logout_hint: Some("mxid:@john:localhost".to_owned()),
        post_logout_redirect_uri: Some(Url::parse("http://localhost:8181/").unwrap()),
        ..Default::default()
    };
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let (url, state) = build_end_session_url(end_session_endpoint, logout_data, &mut rng).unwrap();

    assert_eq!(url.path(), "/end_session");
    let state = assert_matches!(state, Some(s) => s);

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.get("id_token_hint"), None);
    assert_eq!(
        query_pairs.get("logout_hint").unwrap(),
        "mxid:@john:localhost"
    );
    assert_eq!(query_pairs.get("client_id"), None);
    assert_eq!(
        query_pairs.get("post_logout_redirect_uri").unwrap(),
        "http://localhost:8181/"
    );
    assert_eq!(query_pairs.get("ui_locales"), None);
    assert_eq!(query_pairs.get("state").unwrap(), &*state);
}
