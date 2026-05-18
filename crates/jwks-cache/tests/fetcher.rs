// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Integration tests for the JWKS fetcher actor: drives a real Postgres-backed
//! repository factory and a wiremock origin, then asserts the actor's
//! coalescing, freshness, conditional-revalidation, and SWR-refresh
//! behaviours.

use std::sync::Arc;

use chrono::Duration;
use mas_data_model::clock::MockClock;
use mas_jwks_cache::JwksFetcher;
use mas_storage::{RepositoryAccess, RepositoryFactory};
use mas_storage_pg::PgRepositoryFactory;
use serde_json::json;
use sqlx::PgPool;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

fn rsa_key(kid: &str) -> serde_json::Value {
    json!({
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
    })
}

fn jwks_with_kid(kid: &str) -> serde_json::Value {
    json!({ "keys": [rsa_key(kid)] })
}

async fn start_fetcher(pool: PgPool) -> (JwksFetcher, Arc<MockClock>) {
    let factory = Arc::new(PgRepositoryFactory::new(pool));
    let clock = Arc::new(MockClock::default());
    let http = mas_http::reqwest_client();
    // Use _ to discard the JoinHandle; the actor dies when fetcher drops.
    let (fetcher, _) = JwksFetcher::start(http, factory, clock.clone());
    (fetcher, clock)
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn first_fetch_populates_cache(pool: PgPool) {
    let server = MockServer::start().await;
    let uri: Url = format!("{}/jwks", server.uri()).parse().unwrap();
    let body = jwks_with_kid("k1");
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(body)
                .insert_header("Cache-Control", "max-age=300")
                .insert_header("ETag", "\"v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    let (fetcher, _clock) = start_fetcher(pool.clone()).await;

    let result = fetcher.get(uri.clone()).await.unwrap();
    let jwks = result.as_ref().expect("fetch should succeed");
    assert_eq!(jwks.len(), 1);

    // Cache row should be populated.
    let factory = PgRepositoryFactory::new(pool);
    let mut repo = factory.create().await.unwrap();
    let entry = repo.jwks_cache().get(&uri).await.unwrap().expect("row present");
    assert_eq!(entry.etag.as_deref(), Some("\"v1\""));
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn second_get_is_cached(pool: PgPool) {
    let server = MockServer::start().await;
    let uri: Url = format!("{}/jwks", server.uri()).parse().unwrap();
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(jwks_with_kid("k1"))
                .insert_header("Cache-Control", "max-age=300"),
        )
        // First call hits the origin; second is served from cache.
        .expect(1)
        .mount(&server)
        .await;

    let (fetcher, _clock) = start_fetcher(pool).await;

    let r1 = fetcher.get(uri.clone()).await.unwrap();
    assert!(r1.is_ok());
    let r2 = fetcher.get(uri.clone()).await.unwrap();
    assert!(r2.is_ok());
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn revalidation_uses_if_none_match(pool: PgPool) {
    let server = MockServer::start().await;
    let uri: Url = format!("{}/jwks", server.uri()).parse().unwrap();

    // First request: serve the body with an ETag and a tight max-age.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(jwks_with_kid("k1"))
                .insert_header("Cache-Control", "max-age=60")
                .insert_header("ETag", "\"v1\""),
        )
        .expect(1)
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let (fetcher, clock) = start_fetcher(pool).await;
    let r1 = fetcher.get(uri.clone()).await.unwrap();
    assert!(r1.is_ok());

    // Advance past the freshness window so the next Get must revalidate.
    clock.advance(Duration::seconds(120));

    // Second request: origin should see `If-None-Match` and return 304.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .and(header("if-none-match", "\"v1\""))
        .respond_with(
            ResponseTemplate::new(304)
                .insert_header("Cache-Control", "max-age=60")
                .insert_header("ETag", "\"v1\""),
        )
        .expect(1)
        .mount(&server)
        .await;

    let r2 = fetcher.get(uri.clone()).await.unwrap();
    let jwks = r2.as_ref().expect("304 should produce cached body");
    assert_eq!(jwks.len(), 1);
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn forced_refresh_refetches(pool: PgPool) {
    let server = MockServer::start().await;
    let uri: Url = format!("{}/jwks", server.uri()).parse().unwrap();

    // First-call mock, scoped — we'll drop it before the refresh.
    let first = Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(jwks_with_kid("k1"))
                .insert_header("Cache-Control", "max-age=86400"),
        )
        .mount_as_scoped(&server)
        .await;

    let (fetcher, _clock) = start_fetcher(pool.clone()).await;
    let r1 = fetcher.get(uri.clone()).await.unwrap();
    let jwks = r1.as_ref().expect("first fetch ok");
    assert_eq!(jwks.len(), 1);
    drop(first);

    // Refresh: origin now returns a different body.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "keys": [rsa_key("k1"), rsa_key("k2")] }))
                .insert_header("Cache-Control", "max-age=86400"),
        )
        .expect(1)
        .mount(&server)
        .await;

    fetcher.refresh(uri.clone());
    let r2 = fetcher.get(uri.clone()).await.unwrap();
    let jwks = r2.as_ref().expect("post-refresh fetch ok");
    assert_eq!(jwks.len(), 2);

    // And the DB row should now hold both keys too.
    let factory = PgRepositoryFactory::new(pool);
    let mut repo = factory.create().await.unwrap();
    let entry = repo.jwks_cache().get(&uri).await.unwrap().unwrap();
    assert_eq!(entry.jwks.len(), 2);
}

#[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
async fn stale_on_error_serves_cached(pool: PgPool) {
    let server = MockServer::start().await;
    let uri: Url = format!("{}/jwks", server.uri()).parse().unwrap();

    let success_mock = Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(jwks_with_kid("k1"))
                .insert_header("Cache-Control", "max-age=60"),
        )
        .mount_as_scoped(&server)
        .await;

    let (fetcher, clock) = start_fetcher(pool).await;
    let _ = fetcher.get(uri.clone()).await.unwrap();
    drop(success_mock);

    // Expire the cache and have the origin start failing.
    clock.advance(Duration::seconds(120));
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let r = fetcher.get(uri.clone()).await.unwrap();
    let jwks = r.expect("stale-on-error should serve cached body");
    assert_eq!(jwks.len(), 1);
}
