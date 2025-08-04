// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{process::ExitCode, time::Duration};

use clap::Parser;
use figment::Figment;
use mas_config::{AppConfig, ConfigurationSection};
use mas_router::UrlBuilder;
use mas_storage::SystemClock;
use mas_storage_pg::PgRepositoryFactory;
use tracing::{info, info_span};

use crate::{
    lifecycle::LifecycleManager,
    util::{
        database_pool_from_config, homeserver_connection_from_config, mailer_from_config,
        site_config_from_config, templates_from_config, test_mailer_in_background,
    },
};

#[derive(Parser, Debug, Default)]
pub(super) struct Options {}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let shutdown = LifecycleManager::new()?;
        let span = info_span!("cli.worker.init").entered();
        let config = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

        // Connect to the database
        info!("Connecting to the database");
        let pool = database_pool_from_config(&config.database).await?;

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

        let mailer = mailer_from_config(&config.email, &templates)?;
        test_mailer_in_background(&mailer, Duration::from_secs(30));

        let http_client = mas_http::reqwest_client();
        let conn = homeserver_connection_from_config(&config.matrix, http_client);

        drop(config);

        info!("Starting task scheduler");
        mas_tasks::init_and_run(
            PgRepositoryFactory::new(pool.clone()),
            SystemClock::default(),
            &mailer,
            conn,
            url_builder,
            &site_config,
            shutdown.soft_shutdown_token(),
            shutdown.task_tracker(),
        )
        .await?;

        span.exit();

        let exit_code = shutdown.run().await;

        Ok(exit_code)
    }
}
