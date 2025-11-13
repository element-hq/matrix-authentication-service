// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{convert::Infallible, net::IpAddr, sync::Arc};

use axum::extract::{FromRef, FromRequestParts};
use ipnetwork::IpNetwork;
use mas_context::LogContext;
<<<<<<< HEAD
use mas_data_model::{
    BoxClock,
    BoxRng,
    SiteConfig,
    SystemClock,
    //:tchap:
    TchapConfig, //:tchap:end
};
=======
use mas_data_model::{AppVersion, BoxClock, BoxRng, SiteConfig, SystemClock};
>>>>>>> v1.6.0
use mas_handlers::{
    ActivityTracker, BoundActivityTracker, CookieManager, ErrorWrapper, GraphQLSchema, Limiter,
    MetadataCache, RequesterFingerprint, passwords::PasswordManager,
};
use mas_i18n::Translator;
use mas_keystore::{Encrypter, Keystore};
use mas_matrix::HomeserverConnection;
use mas_policy::{Policy, PolicyFactory};
use mas_router::UrlBuilder;
use mas_storage::{BoxRepository, BoxRepositoryFactory, RepositoryFactory};
use mas_storage_pg::PgRepositoryFactory;
use mas_templates::Templates;
use opentelemetry::KeyValue;
use rand::SeedableRng;
use sqlx::PgPool;
use tracing::Instrument;

use crate::{VERSION, telemetry::METER};

#[derive(Clone)]
pub struct AppState {
    pub repository_factory: PgRepositoryFactory,
    pub templates: Templates,
    pub key_store: Keystore,
    pub cookie_manager: CookieManager,
    pub encrypter: Encrypter,
    pub url_builder: UrlBuilder,
    pub homeserver_connection: Arc<dyn HomeserverConnection>,
    pub policy_factory: Arc<PolicyFactory>,
    pub graphql_schema: GraphQLSchema,
    pub http_client: reqwest::Client,
    pub password_manager: PasswordManager,
    pub metadata_cache: MetadataCache,
    pub site_config: SiteConfig,
    pub activity_tracker: ActivityTracker,
    pub trusted_proxies: Vec<IpNetwork>,
    pub limiter: Limiter,
    //:tchap:
    pub tchap_config: TchapConfig,
    //:tchap: end
}

impl AppState {
    /// Init the metrics for the app state.
    pub fn init_metrics(&mut self) {
        let pool = self.repository_factory.pool();
        METER
            .i64_observable_up_down_counter("db.connections.usage")
            .with_description("The number of connections that are currently in `state` described by the state attribute.")
            .with_unit("{connection}")
            .with_callback(move |instrument| {
                let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
                let used = pool.size() - idle;
                instrument.observe(i64::from(idle), &[KeyValue::new("state", "idle")]);
                instrument.observe(i64::from(used), &[KeyValue::new("state", "used")]);
            })
            .build();

        let pool = self.repository_factory.pool();
        METER
            .i64_observable_up_down_counter("db.connections.max")
            .with_description("The maximum number of open connections allowed.")
            .with_unit("{connection}")
            .with_callback(move |instrument| {
                let max_conn = pool.options().get_max_connections();
                instrument.observe(i64::from(max_conn), &[]);
            })
            .build();
    }

    /// Init the metadata cache in the background
    pub fn init_metadata_cache(&self) {
        let factory = self.repository_factory.clone();
        let metadata_cache = self.metadata_cache.clone();
        let http_client = self.http_client.clone();

        tokio::spawn(
            LogContext::new("metadata-cache-warmup")
                .run(async move || {
                    let mut repo = match factory.create().await {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::error!(
                                error = &e as &dyn std::error::Error,
                                "Failed to acquire a database connection"
                            );
                            return;
                        }
                    };

                    if let Err(e) = metadata_cache
                        .warm_up_and_run(
                            &http_client,
                            std::time::Duration::from_secs(60 * 15),
                            &mut repo,
                        )
                        .await
                    {
                        tracing::error!(
                            error = &e as &dyn std::error::Error,
                            "Failed to warm up the metadata cache"
                        );
                    }
                })
                .instrument(tracing::info_span!("metadata_cache.background_warmup")),
        );
    }
}

// XXX(quenting): we only use this for the healthcheck endpoint, checking the db
// should be part of the repository
impl FromRef<AppState> for PgPool {
    fn from_ref(input: &AppState) -> Self {
        input.repository_factory.pool()
    }
}

impl FromRef<AppState> for BoxRepositoryFactory {
    fn from_ref(input: &AppState) -> Self {
        input.repository_factory.clone().boxed()
    }
}

impl FromRef<AppState> for GraphQLSchema {
    fn from_ref(input: &AppState) -> Self {
        input.graphql_schema.clone()
    }
}

impl FromRef<AppState> for Templates {
    fn from_ref(input: &AppState) -> Self {
        input.templates.clone()
    }
}

impl FromRef<AppState> for Arc<Translator> {
    fn from_ref(input: &AppState) -> Self {
        input.templates.translator()
    }
}

impl FromRef<AppState> for Keystore {
    fn from_ref(input: &AppState) -> Self {
        input.key_store.clone()
    }
}

impl FromRef<AppState> for Encrypter {
    fn from_ref(input: &AppState) -> Self {
        input.encrypter.clone()
    }
}

impl FromRef<AppState> for UrlBuilder {
    fn from_ref(input: &AppState) -> Self {
        input.url_builder.clone()
    }
}

impl FromRef<AppState> for reqwest::Client {
    fn from_ref(input: &AppState) -> Self {
        input.http_client.clone()
    }
}

impl FromRef<AppState> for PasswordManager {
    fn from_ref(input: &AppState) -> Self {
        input.password_manager.clone()
    }
}

impl FromRef<AppState> for CookieManager {
    fn from_ref(input: &AppState) -> Self {
        input.cookie_manager.clone()
    }
}

impl FromRef<AppState> for MetadataCache {
    fn from_ref(input: &AppState) -> Self {
        input.metadata_cache.clone()
    }
}

impl FromRef<AppState> for SiteConfig {
    fn from_ref(input: &AppState) -> Self {
        input.site_config.clone()
    }
}

impl FromRef<AppState> for Limiter {
    fn from_ref(input: &AppState) -> Self {
        input.limiter.clone()
    }
}

impl FromRef<AppState> for Arc<PolicyFactory> {
    fn from_ref(input: &AppState) -> Self {
        input.policy_factory.clone()
    }
}

impl FromRef<AppState> for Arc<dyn HomeserverConnection> {
    fn from_ref(input: &AppState) -> Self {
        Arc::clone(&input.homeserver_connection)
    }
}

<<<<<<< HEAD
//:tchap:
impl FromRef<AppState> for TchapConfig {
    fn from_ref(input: &AppState) -> Self {
        input.tchap_config.clone()
    }
}
//:tchap:end
=======
impl FromRef<AppState> for AppVersion {
    fn from_ref(_input: &AppState) -> Self {
        AppVersion(VERSION)
    }
}
>>>>>>> v1.6.0

impl FromRequestParts<AppState> for BoxClock {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let clock = SystemClock::default();
        Ok(Box::new(clock))
    }
}

impl FromRequestParts<AppState> for BoxRng {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // This rng is used to source the local rng
        #[allow(clippy::disallowed_methods)]
        let rng = rand::thread_rng();

        let rng = rand_chacha::ChaChaRng::from_rng(rng).expect("Failed to seed RNG");
        Ok(Box::new(rng))
    }
}

impl FromRequestParts<AppState> for Policy {
    type Rejection = ErrorWrapper<mas_policy::InstantiateError>;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let policy = state.policy_factory.instantiate().await?;
        Ok(policy)
    }
}

impl FromRequestParts<AppState> for ActivityTracker {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(state.activity_tracker.clone())
    }
}

fn infer_client_ip(
    parts: &axum::http::request::Parts,
    trusted_proxies: &[IpNetwork],
) -> Option<IpAddr> {
    let connection_info = parts.extensions.get::<mas_listener::ConnectionInfo>();

    let peer = if let Some(info) = connection_info {
        // We can always trust the proxy protocol to give us the correct IP address
        if let Some(proxy) = info.get_proxy_ref()
            && let Some(source) = proxy.source()
        {
            return Some(source.ip());
        }

        info.get_peer_addr().map(|addr| addr.ip())
    } else {
        None
    };

    // Get the list of IPs from the X-Forwarded-For header
    let peers_from_header = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').filter_map(|v| v.parse().ok()))
        .into_iter()
        .flatten();

    // This constructs a list of IP addresses that might be the client's IP address.
    // Each intermediate proxy is supposed to add the client's IP address to front
    // of the list. We are effectively adding the IP we got from the socket to the
    // front of the list.
    // We also call `to_canonical` so that IPv6-mapped IPv4 addresses
    // (::ffff:A.B.C.D) are converted to IPv4.
    let peer_list: Vec<IpAddr> = peer
        .into_iter()
        .chain(peers_from_header)
        .map(|ip| ip.to_canonical())
        .collect();

    // We'll fallback to the first IP in the list if all the IPs we got are trusted
    let fallback = peer_list.first().copied();

    // Now we go through the list, and the IP of the client is the first IP that is
    // not in the list of trusted proxies, starting from the back.
    let client_ip = peer_list
        .iter()
        .rfind(|ip| !trusted_proxies.iter().any(|network| network.contains(**ip)))
        .copied();

    client_ip.or(fallback)
}

impl FromRequestParts<AppState> for BoundActivityTracker {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // TODO: we may infer the IP twice, for the activity tracker and the limiter
        let ip = infer_client_ip(parts, &state.trusted_proxies);
        tracing::debug!(ip = ?ip, "Inferred client IP address");
        Ok(state.activity_tracker.clone().bind(ip))
    }
}

impl FromRequestParts<AppState> for RequesterFingerprint {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // TODO: we may infer the IP twice, for the activity tracker and the limiter
        let ip = infer_client_ip(parts, &state.trusted_proxies);

        if let Some(ip) = ip {
            Ok(RequesterFingerprint::new(ip))
        } else {
            // If we can't infer the IP address, we'll just use an empty fingerprint and
            // warn about it
            tracing::warn!(
                "Could not infer client IP address for an operation which rate-limits based on IP addresses"
            );
            Ok(RequesterFingerprint::EMPTY)
        }
    }
}

impl FromRequestParts<AppState> for BoxRepository {
    type Rejection = ErrorWrapper<mas_storage::RepositoryError>;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let repo = state.repository_factory.create().await?;
        Ok(repo)
    }
}
