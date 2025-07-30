// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::BTreeSet, process::ExitCode, sync::Arc, time::Duration};

use anyhow::Context;
use clap::Parser;
use figment::Figment;
use itertools::Itertools;
use mas_config::{
    AppConfig, ClientsConfig, ConfigurationSection, ConfigurationSectionExt, UpstreamOAuth2Config,
};
use mas_context::LogContext;
use mas_handlers::{ActivityTracker, CookieManager, Limiter, MetadataCache};
use mas_listener::server::Server;
use mas_router::UrlBuilder;
use mas_storage::SystemClock;
use mas_storage_pg::{MIGRATOR, PgRepositoryFactory};
use sqlx::migrate::Migrate;
use tracing::{Instrument, info, info_span, warn};

use crate::{
    app_state::AppState,
    lifecycle::LifecycleManager,
    util::{
        database_pool_from_config, homeserver_connection_from_config,
        load_policy_factory_dynamic_data_continuously, mailer_from_config,
        password_manager_from_config, policy_factory_from_config, site_config_from_config,
        templates_from_config, test_mailer_in_background,
    },
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug, Default)]
pub(super) struct Options {
    /// Do not apply pending database migrations on start
    #[arg(long)]
    no_migrate: bool,

    /// DEPRECATED: default is to apply pending migrations, use `--no-migrate`
    /// to disable
    #[arg(long, hide = true)]
    migrate: bool,

    /// Do not start the task worker
    #[arg(long)]
    no_worker: bool,

    /// Do not sync the configuration with the database
    #[arg(long)]
    no_sync: bool,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let span = info_span!("cli.run.init").entered();
        let mut shutdown = LifecycleManager::new()?;
        let config = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

        info!(version = crate::VERSION, "Starting up");

        if self.migrate {
            warn!(
                "The `--migrate` flag is deprecated and will be removed in a future release. Please use `--no-migrate` to disable automatic migrations on startup."
            );
        }

        // Connect to the database
        info!("Connecting to the database");
        let pool = database_pool_from_config(&config.database).await?;

        if self.no_migrate {
            // Check that we applied all the migrations
            let mut conn = pool.acquire().await?;
            let applied = conn.list_applied_migrations().await?;
            let applied: BTreeSet<_> = applied.into_iter().map(|m| m.version).collect();
            let has_missing_migrations = MIGRATOR.iter().any(|m| !applied.contains(&m.version));
            if has_missing_migrations {
                // Refuse to start if there are pending migrations
                return Err(anyhow::anyhow!(
                    "The server is running with `--no-migrate` but there are pending. Please run them first with `mas-cli database migrate`, or omit the `--no-migrate` flag to apply them automatically on startup."
                ));
            }
        } else {
            info!("Running pending database migrations");
            MIGRATOR
                .run(&pool)
                .instrument(info_span!("db.migrate"))
                .await
                .context("could not run database migrations")?;
        }

        let encrypter = config.secrets.encrypter().await?;

        if self.no_sync {
            info!("Skipping configuration sync");
        } else {
            // Sync the configuration with the database
            let mut conn = pool.acquire().await?;
            let clients_config =
                ClientsConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
            let upstream_oauth2_config = UpstreamOAuth2Config::extract_or_default(figment)
                .map_err(anyhow::Error::from_boxed)?;

            crate::sync::config_sync(
                upstream_oauth2_config,
                clients_config,
                &mut conn,
                &encrypter,
                &SystemClock::default(),
                false,
                false,
            )
            .await
            .context("could not sync the configuration with the database")?;
        }

        // Initialize the key store
        let key_store = config
            .secrets
            .key_store()
            .await
            .context("could not import keys from config")?;

        let cookie_manager = CookieManager::derive_from(
            config.http.public_base.clone(),
            &config.secrets.encryption().await?,
        );

        // Load and compile the WASM policies (and fallback to the default embedded one)
        info!("Loading and compiling the policy module");
        let policy_factory = policy_factory_from_config(&config.policy, &config.matrix).await?;
        let policy_factory = Arc::new(policy_factory);

        load_policy_factory_dynamic_data_continuously(
            &policy_factory,
            PgRepositoryFactory::new(pool.clone()).boxed(),
            shutdown.soft_shutdown_token(),
            shutdown.task_tracker(),
        )
        .await?;

        let url_builder = UrlBuilder::new(
            config.http.public_base.clone(),
            config.http.issuer.clone(),
            None,
        );

        // Load the site configuration
        let site_config = site_config_from_config(
            &config.branding,
            &config.matrix,
            &config.experimental,
            &config.passwords,
            &config.account,
            &config.captcha,
        )?;

        // Load and compile the templates
        let templates =
            templates_from_config(&config.templates, &site_config, &url_builder).await?;
        shutdown.register_reloadable(&templates);

        let http_client = mas_http::reqwest_client();

        let homeserver_connection =
            homeserver_connection_from_config(&config.matrix, http_client.clone());

        if !self.no_worker {
            let mailer = mailer_from_config(&config.email, &templates)?;
            test_mailer_in_background(&mailer, Duration::from_secs(30));

            info!("Starting task worker");
            mas_tasks::init_and_run(
                PgRepositoryFactory::new(pool.clone()),
                SystemClock::default(),
                &mailer,
                homeserver_connection.clone(),
                url_builder.clone(),
                &site_config,
                shutdown.soft_shutdown_token(),
                shutdown.task_tracker(),
            )
            .await?;
        }

        let listeners_config = config.http.listeners.clone();

        let password_manager = password_manager_from_config(&config.passwords).await?;

        // The upstream OIDC metadata cache
        let metadata_cache = MetadataCache::new();

        // Initialize the activity tracker
        // Activity is flushed every minute
        let activity_tracker = ActivityTracker::new(
            PgRepositoryFactory::new(pool.clone()).boxed(),
            Duration::from_secs(60),
            shutdown.task_tracker(),
            shutdown.soft_shutdown_token(),
        );

        shutdown.register_reloadable(&activity_tracker);

        let trusted_proxies = config.http.trusted_proxies.clone();

        // Build a rate limiter.
        // This should not raise an error here as the config should already have been
        // validated.
        let limiter = Limiter::new(&config.rate_limiting)
            .context("rate-limiting configuration is not valid")?;

        // Explicitly the config to properly zeroize secret keys
        drop(config);

        limiter.start();

        let graphql_schema = mas_handlers::graphql_schema(
            PgRepositoryFactory::new(pool.clone()).boxed(),
            &policy_factory,
            homeserver_connection.clone(),
            site_config.clone(),
            password_manager.clone(),
            url_builder.clone(),
            limiter.clone(),
        );

        let state = {
            let mut s = AppState {
                repository_factory: PgRepositoryFactory::new(pool),
                templates,
                key_store,
                cookie_manager,
                encrypter,
                url_builder,
                homeserver_connection,
                policy_factory,
                graphql_schema,
                http_client,
                password_manager,
                metadata_cache,
                site_config,
                activity_tracker,
                trusted_proxies,
                limiter,
            };
            s.init_metrics();
            s.init_metadata_cache();
            s
        };

        let mut fd_manager = listenfd::ListenFd::from_env();

        let servers: Vec<Server<_>> = listeners_config
            .into_iter()
            .map(|config| {
                // Let's first grab all the listeners
                let listeners = crate::server::build_listeners(&mut fd_manager, &config.binds)?;

                // Load the TLS config
                let tls_config = if let Some(tls_config) = config.tls.as_ref() {
                    let tls_config = crate::server::build_tls_server_config(tls_config)?;
                    Some(Arc::new(tls_config))
                } else {
                    None
                };

                // and build the router
                let router = crate::server::build_router(
                    state.clone(),
                    &config.resources,
                    config.prefix.as_deref(),
                    config.name.as_deref(),
                );


                // Display some informations about where we'll be serving connections
                let proto = if config.tls.is_some() { "https" } else { "http" };
                let prefix = config.prefix.unwrap_or_default();
                let addresses= listeners
                    .iter()
                    .map(|listener| {
                        if let Ok(addr) = listener.local_addr() {
                            format!("{proto}://{addr:?}{prefix}")
                        } else {
                            warn!("Could not get local address for listener, something might be wrong!");
                            format!("{proto}://???{prefix}")
                        }
                    })
                    .join(", ");

                let additional = if config.proxy_protocol {
                    "(with Proxy Protocol)"
                } else {
                    ""
                };

                info!(
                    "Listening on {addresses} with resources {resources:?} {additional}",
                    resources = &config.resources
                );

                anyhow::Ok(listeners.into_iter().map(move |listener| {
                    let mut server = Server::new(listener, router.clone());
                    if let Some(tls_config) = &tls_config {
                        server = server.with_tls(tls_config.clone());
                    }
                    if config.proxy_protocol {
                        server = server.with_proxy();
                    }
                    server
                }))
            })
            .flatten_ok()
            .collect::<Result<Vec<_>, _>>()?;

        span.exit();

        shutdown
            .task_tracker()
            .spawn(LogContext::new("run-servers").run(|| {
                mas_listener::server::run_servers(
                    servers,
                    shutdown.soft_shutdown_token(),
                    shutdown.hard_shutdown_token(),
                )
            }));

        let exit_code = shutdown.run().await;

        Ok(exit_code)
    }
}
