// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{collections::HashMap, sync::Arc};

use mas_data_model::{
    UpstreamOAuthProvider, UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderPkceMode,
};
use mas_iana::oauth::PkceCodeChallengeMethod;
use mas_oidc_client::error::DiscoveryError;
use mas_storage::{upstream_oauth2::UpstreamOAuthProviderRepository, RepositoryAccess};
use oauth2_types::oidc::VerifiedProviderMetadata;
use tokio::sync::RwLock;
use url::Url;

/// A high-level layer over metadata cache and provider configuration, which
/// resolves endpoint overrides and discovery modes.
pub struct LazyProviderInfos<'a> {
    cache: &'a MetadataCache,
    provider: &'a UpstreamOAuthProvider,
    client: &'a reqwest::Client,
    loaded_metadata: Option<Arc<VerifiedProviderMetadata>>,
}

impl<'a> LazyProviderInfos<'a> {
    pub fn new(
        cache: &'a MetadataCache,
        provider: &'a UpstreamOAuthProvider,
        client: &'a reqwest::Client,
    ) -> Self {
        Self {
            cache,
            provider,
            client,
            loaded_metadata: None,
        }
    }

    /// Trigger the discovery process and return the metadata if discovery is
    /// enabled.
    pub async fn maybe_discover<'b>(
        &'b mut self,
    ) -> Result<Option<&'b VerifiedProviderMetadata>, DiscoveryError> {
        match self.load().await {
            Ok(metadata) => Ok(Some(metadata)),
            Err(DiscoveryError::Disabled) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn load<'b>(&'b mut self) -> Result<&'b VerifiedProviderMetadata, DiscoveryError> {
        if self.loaded_metadata.is_none() {
            let verify = match self.provider.discovery_mode {
                UpstreamOAuthProviderDiscoveryMode::Oidc => true,
                UpstreamOAuthProviderDiscoveryMode::Insecure => false,
                UpstreamOAuthProviderDiscoveryMode::Disabled => {
                    return Err(DiscoveryError::Disabled)
                }
            };

            let metadata = self
                .cache
                .get(self.client, &self.provider.issuer, verify)
                .await?;

            self.loaded_metadata = Some(metadata);
        }

        Ok(self.loaded_metadata.as_ref().unwrap())
    }

    /// Get the JWKS URI for the provider.
    ///
    /// Uses [`UpstreamOAuthProvider.jwks_uri_override`] if set, otherwise uses
    /// the one from discovery.
    pub async fn jwks_uri(&mut self) -> Result<&Url, DiscoveryError> {
        if let Some(jwks_uri) = &self.provider.jwks_uri_override {
            return Ok(jwks_uri);
        }

        Ok(self.load().await?.jwks_uri())
    }

    /// Get the authorization endpoint for the provider.
    ///
    /// Uses [`UpstreamOAuthProvider.authorization_endpoint_override`] if set,
    /// otherwise uses the one from discovery.
    pub async fn authorization_endpoint(&mut self) -> Result<&Url, DiscoveryError> {
        if let Some(authorization_endpoint) = &self.provider.authorization_endpoint_override {
            return Ok(authorization_endpoint);
        }

        Ok(self.load().await?.authorization_endpoint())
    }

    /// Get the token endpoint for the provider.
    ///
    /// Uses [`UpstreamOAuthProvider.token_endpoint_override`] if set, otherwise
    /// uses the one from discovery.
    pub async fn token_endpoint(&mut self) -> Result<&Url, DiscoveryError> {
        if let Some(token_endpoint) = &self.provider.token_endpoint_override {
            return Ok(token_endpoint);
        }

        Ok(self.load().await?.token_endpoint())
    }

    /// Get the PKCE methods supported by the provider.
    ///
    /// If the mode is set to auto, it will use the ones from discovery,
    /// defaulting to none if discovery is disabled.
    pub async fn pkce_methods(
        &mut self,
    ) -> Result<Option<Vec<PkceCodeChallengeMethod>>, DiscoveryError> {
        let methods = match self.provider.pkce_mode {
            UpstreamOAuthProviderPkceMode::Auto => self
                .maybe_discover()
                .await?
                .and_then(|metadata| metadata.code_challenge_methods_supported.clone()),
            UpstreamOAuthProviderPkceMode::S256 => Some(vec![PkceCodeChallengeMethod::S256]),
            UpstreamOAuthProviderPkceMode::Disabled => None,
        };

        Ok(methods)
    }
}

/// A simple OIDC metadata cache
///
/// It never evicts entries, does not cache failures and has no locking.
/// It can also be refreshed in the background, and warmed up on startup.
/// It is good enough for our use case.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Default)]
pub struct MetadataCache {
    cache: Arc<RwLock<HashMap<String, Arc<VerifiedProviderMetadata>>>>,
    insecure_cache: Arc<RwLock<HashMap<String, Arc<VerifiedProviderMetadata>>>>,
}

impl MetadataCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Warm up the cache by fetching all the known providers from the database
    /// and inserting them into the cache.
    ///
    /// This spawns a background task that will refresh the cache at the given
    /// interval.
    #[tracing::instrument(name = "metadata_cache.warm_up_and_run", skip_all, err)]
    pub async fn warm_up_and_run<R: RepositoryAccess>(
        &self,
        client: &reqwest::Client,
        interval: std::time::Duration,
        repository: &mut R,
    ) -> Result<tokio::task::JoinHandle<()>, R::Error> {
        let providers = repository.upstream_oauth_provider().all_enabled().await?;

        for provider in providers {
            let verify = match provider.discovery_mode {
                UpstreamOAuthProviderDiscoveryMode::Oidc => true,
                UpstreamOAuthProviderDiscoveryMode::Insecure => false,
                UpstreamOAuthProviderDiscoveryMode::Disabled => continue,
            };

            if let Err(e) = self.fetch(client, &provider.issuer, verify).await {
                tracing::error!(issuer = %provider.issuer, error = &e as &dyn std::error::Error, "Failed to fetch provider metadata");
            }
        }

        // Spawn a background task to refresh the cache regularly
        let cache = self.clone();
        let client = client.clone();
        Ok(tokio::spawn(async move {
            loop {
                // Re-fetch the known metadata at the given interval
                tokio::time::sleep(interval).await;
                cache.refresh_all(&client).await;
            }
        }))
    }

    #[tracing::instrument(name = "metadata_cache.fetch", fields(%issuer), skip_all, err)]
    async fn fetch(
        &self,
        client: &reqwest::Client,
        issuer: &str,
        verify: bool,
    ) -> Result<Arc<VerifiedProviderMetadata>, DiscoveryError> {
        if verify {
            let metadata = mas_oidc_client::requests::discovery::discover(client, issuer).await?;
            let metadata = Arc::new(metadata);

            self.cache
                .write()
                .await
                .insert(issuer.to_owned(), metadata.clone());

            Ok(metadata)
        } else {
            let metadata =
                mas_oidc_client::requests::discovery::insecure_discover(client, issuer).await?;
            let metadata = Arc::new(metadata);

            self.insecure_cache
                .write()
                .await
                .insert(issuer.to_owned(), metadata.clone());

            Ok(metadata)
        }
    }

    /// Get the metadata for the given issuer.
    #[tracing::instrument(name = "metadata_cache.get", fields(%issuer), skip_all, err)]
    pub async fn get(
        &self,
        client: &reqwest::Client,
        issuer: &str,
        verify: bool,
    ) -> Result<Arc<VerifiedProviderMetadata>, DiscoveryError> {
        let cache = if verify {
            self.cache.read().await
        } else {
            self.insecure_cache.read().await
        };

        if let Some(metadata) = cache.get(issuer) {
            return Ok(Arc::clone(metadata));
        }
        // Drop the cache guard so that we don't deadlock when we try to fetch
        drop(cache);

        let metadata = self.fetch(client, issuer, verify).await?;
        Ok(metadata)
    }

    #[tracing::instrument(name = "metadata_cache.refresh_all", skip_all)]
    async fn refresh_all(&self, client: &reqwest::Client) {
        // Grab all the keys first to avoid locking the cache for too long
        let keys: Vec<String> = {
            let cache = self.cache.read().await;
            cache.keys().cloned().collect()
        };

        for issuer in keys {
            if let Err(e) = self.fetch(client, &issuer, true).await {
                tracing::error!(issuer = %issuer, error = &e as &dyn std::error::Error, "Failed to refresh provider metadata");
            }
        }

        // Do the same for the insecure cache
        let keys: Vec<String> = {
            let cache = self.insecure_cache.read().await;
            cache.keys().cloned().collect()
        };

        for issuer in keys {
            if let Err(e) = self.fetch(client, &issuer, false).await {
                tracing::error!(issuer = %issuer, error = &e as &dyn std::error::Error, "Failed to refresh provider metadata");
            }
        }
    }
}

/* TODO: redo those tests
#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use hyper::{body::Bytes, Request, Response, StatusCode};
    use mas_data_model::UpstreamOAuthProviderClaimsImports;
    use mas_http::BoxCloneSyncService;
    use mas_iana::oauth::OAuthClientAuthenticationMethod;
    use mas_storage::{clock::MockClock, Clock};
    use oauth2_types::scope::{Scope, OPENID};
    use tower::BoxError;
    use ulid::Ulid;

    use super::*;
    use crate::test_utils::setup;

    #[tokio::test]
    async fn test_metadata_cache() {
        setup();
        let calls = Arc::new(AtomicUsize::new(0));
        let closure_calls = Arc::clone(&calls);
        let handler = move |req: Request<Bytes>| {
            let calls = Arc::clone(&closure_calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);

                let body = match req.uri().authority().unwrap().as_str() {
                    "valid.example.com" => Bytes::from_static(
                        br#"{
                            "issuer": "https://valid.example.com/",
                            "authorization_endpoint": "https://valid.example.com/authorize",
                            "token_endpoint": "https://valid.example.com/token",
                            "jwks_uri": "https://valid.example.com/jwks",
                            "response_types_supported": [
                                "code"
                            ],
                            "grant_types_supported": [
                                "authorization_code"
                            ],
                            "subject_types_supported": [
                                "public"
                            ],
                            "id_token_signing_alg_values_supported": [
                                "RS256"
                            ],
                            "scopes_supported": [
                                "openid",
                                "profile",
                                "email"
                            ]
                        }"#,
                    ),
                    "insecure.example.com" => Bytes::from_static(
                        br#"{
                            "issuer": "http://insecure.example.com/",
                            "authorization_endpoint": "http://insecure.example.com/authorize",
                            "token_endpoint": "http://insecure.example.com/token",
                            "jwks_uri": "http://insecure.example.com/jwks",
                            "response_types_supported": [
                                "code"
                            ],
                            "grant_types_supported": [
                                "authorization_code"
                            ],
                            "subject_types_supported": [
                                "public"
                            ],
                            "id_token_signing_alg_values_supported": [
                                "RS256"
                            ],
                            "scopes_supported": [
                                "openid",
                                "profile",
                                "email"
                            ]
                        }"#,
                    ),
                    _ => Bytes::default(),
                };

                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::OK;
                Ok::<_, BoxError>(response)
            }
        };

        let service = BoxCloneSyncService::new(tower::service_fn(handler));
        let cache = MetadataCache::new();

        // An inexistant issuer should fail
        cache
            .get(&service, "https://inexistant.example.com/", true)
            .await
            .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // A valid issuer should succeed
        cache
            .get(&service, "https://valid.example.com/", true)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // Calling again should not trigger a new fetch
        cache
            .get(&service, "https://valid.example.com/", true)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // An insecure issuer should work with insecure discovery
        cache
            .get(&service, "http://insecure.example.com/", false)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // Doing it again shpoild not trigger a new fetch
        cache
            .get(&service, "http://insecure.example.com/", false)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // But it should fail with secure discovery
        // Note that it still fetched because secure and insecure caches are distinct
        cache
            .get(&service, "http://insecure.example.com/", true)
            .await
            .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 4);

        // Calling refresh should refresh all the known valid issuers
        cache.refresh_all(&service).await;
        assert_eq!(calls.load(Ordering::SeqCst), 6);
    }

    #[tokio::test]
    async fn test_lazy_provider_infos() {
        setup();
        let calls = Arc::new(AtomicUsize::new(0));
        let closure_calls = Arc::clone(&calls);
        let handler = move |req: Request<Bytes>| {
            let calls = Arc::clone(&closure_calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);

                let body = match req.uri().authority().unwrap().as_str() {
                    "valid.example.com" => Bytes::from_static(
                        br#"{
                            "issuer": "https://valid.example.com/",
                            "authorization_endpoint": "https://valid.example.com/authorize",
                            "token_endpoint": "https://valid.example.com/token",
                            "jwks_uri": "https://valid.example.com/jwks",
                            "response_types_supported": [
                                "code"
                            ],
                            "grant_types_supported": [
                                "authorization_code"
                            ],
                            "subject_types_supported": [
                                "public"
                            ],
                            "id_token_signing_alg_values_supported": [
                                "RS256"
                            ],
                            "scopes_supported": [
                                "openid",
                                "profile",
                                "email"
                            ]
                        }"#,
                    ),
                    "insecure.example.com" => Bytes::from_static(
                        br#"{
                            "issuer": "http://insecure.example.com/",
                            "authorization_endpoint": "http://insecure.example.com/authorize",
                            "token_endpoint": "http://insecure.example.com/token",
                            "jwks_uri": "http://insecure.example.com/jwks",
                            "response_types_supported": [
                                "code"
                            ],
                            "grant_types_supported": [
                                "authorization_code"
                            ],
                            "subject_types_supported": [
                                "public"
                            ],
                            "id_token_signing_alg_values_supported": [
                                "RS256"
                            ],
                            "scopes_supported": [
                                "openid",
                                "profile",
                                "email"
                            ]
                        }"#,
                    ),
                    _ => Bytes::default(),
                };

                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::OK;
                Ok::<_, BoxError>(response)
            }
        };

        let clock = MockClock::default();
        let service = BoxCloneSyncService::new(tower::service_fn(handler));
        let provider = UpstreamOAuthProvider {
            id: Ulid::nil(),
            issuer: "https://valid.example.com/".to_owned(),
            human_name: Some("Example Ltd.".to_owned()),
            brand_name: None,
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            scope: Scope::from_iter([OPENID]),
            client_id: "client_id".to_owned(),
            encrypted_client_secret: None,
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: OAuthClientAuthenticationMethod::None,
            created_at: clock.now(),
            disabled_at: None,
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            additional_authorization_parameters: Vec::new(),
        };

        // Without any override, it should just use discovery
        {
            let cache = MetadataCache::new();
            let mut lazy_metadata = LazyProviderInfos::new(&cache, &provider, &service);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            lazy_metadata.maybe_discover().await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                lazy_metadata
                    .authorization_endpoint()
                    .await
                    .unwrap()
                    .as_str(),
                "https://valid.example.com/authorize"
            );
        }

        // Test overriding endpoints
        {
            let provider = UpstreamOAuthProvider {
                jwks_uri_override: Some("https://valid.example.com/jwks_override".parse().unwrap()),
                authorization_endpoint_override: Some(
                    "https://valid.example.com/authorize_override"
                        .parse()
                        .unwrap(),
                ),
                token_endpoint_override: Some(
                    "https://valid.example.com/token_override".parse().unwrap(),
                ),
                ..provider.clone()
            };
            let cache = MetadataCache::new();
            let mut lazy_metadata = LazyProviderInfos::new(&cache, &provider, &service);
            assert_eq!(
                lazy_metadata.jwks_uri().await.unwrap().as_str(),
                "https://valid.example.com/jwks_override"
            );
            assert_eq!(
                lazy_metadata
                    .authorization_endpoint()
                    .await
                    .unwrap()
                    .as_str(),
                "https://valid.example.com/authorize_override"
            );
            assert_eq!(
                lazy_metadata.token_endpoint().await.unwrap().as_str(),
                "https://valid.example.com/token_override"
            );
            // This shouldn't trigger a new fetch as the endpoint is overriden
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }

        // Insecure providers don't work with secure discovery
        {
            let provider = UpstreamOAuthProvider {
                issuer: "http://insecure.example.com/".to_owned(),
                ..provider.clone()
            };
            let cache = MetadataCache::new();
            let mut lazy_metadata = LazyProviderInfos::new(&cache, &provider, &service);
            lazy_metadata.authorization_endpoint().await.unwrap_err();
            // This triggered a fetch, even though it failed
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }

        // Insecure providers work with insecure discovery
        {
            let provider = UpstreamOAuthProvider {
                issuer: "http://insecure.example.com/".to_owned(),
                discovery_mode: UpstreamOAuthProviderDiscoveryMode::Insecure,
                ..provider.clone()
            };
            let cache = MetadataCache::new();
            let mut lazy_metadata = LazyProviderInfos::new(&cache, &provider, &service);
            assert_eq!(
                lazy_metadata
                    .authorization_endpoint()
                    .await
                    .unwrap()
                    .as_str(),
                "http://insecure.example.com/authorize"
            );
            // This triggered a fetch
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        }

        // Getting endpoints when discovery is disabled only works for overriden ones
        {
            let provider = UpstreamOAuthProvider {
                discovery_mode: UpstreamOAuthProviderDiscoveryMode::Disabled,
                authorization_endpoint_override: Some(
                    Url::parse("https://valid.example.com/authorize_override").unwrap(),
                ),
                token_endpoint_override: None,
                ..provider.clone()
            };
            let cache = MetadataCache::new();
            let mut lazy_metadata = LazyProviderInfos::new(&cache, &provider, &service);
            // This should not fail, but also does nothing
            assert!(lazy_metadata.maybe_discover().await.unwrap().is_none());
            assert_eq!(
                lazy_metadata
                    .authorization_endpoint()
                    .await
                    .unwrap()
                    .as_str(),
                "https://valid.example.com/authorize_override"
            );
            assert!(matches!(
                lazy_metadata.token_endpoint().await,
                Err(DiscoveryError::Disabled),
            ));
            // This did not trigger a fetch
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        }
    }
}
*/
