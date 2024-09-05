// Copyright (C) 2024 New Vector Ltd.
// Copyright 2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::collections::HashMap;

use mas_oidc_client::requests::account_management::{
    build_account_management_url, AccountManagementActionFull,
};
use url::Url;

#[test]
fn build_url() {
    let account_management_uri = Url::parse("http://localhost/account_management/").unwrap();

    // No params
    let url = build_account_management_url(account_management_uri.clone(), None, None).unwrap();

    assert_eq!(url.query(), None);

    // Action without device ID.
    let url = build_account_management_url(
        account_management_uri.clone(),
        Some(AccountManagementActionFull::Profile),
        None,
    )
    .unwrap();

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.len(), 1);
    assert_eq!(query_pairs.get("action").unwrap(), "org.matrix.profile");

    // Action with device ID.
    let url = build_account_management_url(
        account_management_uri.clone(),
        Some(AccountManagementActionFull::SessionEnd {
            device_id: "mydevice".to_owned(),
        }),
        None,
    )
    .unwrap();

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.len(), 2);
    assert_eq!(query_pairs.get("action").unwrap(), "org.matrix.session_end");
    assert_eq!(query_pairs.get("device_id").unwrap(), "mydevice");

    // ID Token hint.
    let url = build_account_management_url(
        account_management_uri.clone(),
        None,
        Some("anidtokenthat.might.looksomethinglikethis".to_owned()),
    )
    .unwrap();

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.len(), 1);
    assert_eq!(
        query_pairs.get("id_token_hint").unwrap(),
        "anidtokenthat.might.looksomethinglikethis"
    );

    // Action without device ID and ID Token hint.
    let url = build_account_management_url(
        account_management_uri.clone(),
        Some(AccountManagementActionFull::AccountDeactivate),
        Some("anotheridtokenthat.might.looksomethinglikethis".to_owned()),
    )
    .unwrap();

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.len(), 2);
    assert_eq!(
        query_pairs.get("action").unwrap(),
        "org.matrix.account_deactivate"
    );
    assert_eq!(
        query_pairs.get("id_token_hint").unwrap(),
        "anotheridtokenthat.might.looksomethinglikethis"
    );

    // Action with device ID and ID Token hint.
    let url = build_account_management_url(
        account_management_uri,
        Some(AccountManagementActionFull::SessionView {
            device_id: "myseconddevice".to_owned(),
        }),
        Some("athirdidtokenthat.might.looksomethinglikethis".to_owned()),
    )
    .unwrap();

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.len(), 3);
    assert_eq!(
        query_pairs.get("action").unwrap(),
        "org.matrix.session_view"
    );
    assert_eq!(query_pairs.get("device_id").unwrap(), "myseconddevice");
    assert_eq!(
        query_pairs.get("id_token_hint").unwrap(),
        "athirdidtokenthat.might.looksomethinglikethis"
    );

    // Account management URI with a query already.
    let account_management_uri_with_query =
        Url::parse("http://localhost/account_management?param=value").unwrap();

    let url = build_account_management_url(
        account_management_uri_with_query,
        Some(AccountManagementActionFull::SessionsList),
        Some("afinalidtokenthat.might.looksomethinglikethis".to_owned()),
    )
    .unwrap();

    let query_pairs = url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(query_pairs.len(), 3);
    assert_eq!(
        query_pairs.get("action").unwrap(),
        "org.matrix.sessions_list"
    );
    assert_eq!(
        query_pairs.get("id_token_hint").unwrap(),
        "afinalidtokenthat.might.looksomethinglikethis"
    );
}
