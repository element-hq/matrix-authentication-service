// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::process::ExitCode;

use clap::Parser;
use figment::Figment;
use mas_config::{AppConfig, ConfigurationSection};
use mas_matrix_synapse::SynapseConnection;
use mas_router::UrlBuilder;
use tracing::{info, info_span};

use crate::{
    shutdown::ShutdownManager,
    util::{
        database_pool_from_config, mailer_from_config, site_config_from_config,
        templates_from_config,
    },
};

#[derive(Parser, Debug, Default)]
pub(super) struct Options {}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let shutdown = ShutdownManager::new()?;
        let span = info_span!("cli.worker.init").entered();
        let config = AppConfig::extract(figment)?;

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
        mailer.test_connection().await?;

        let http_client = mas_http::reqwest_client();
        let conn = SynapseConnection::new(
            config.matrix.homeserver.clone(),
            config.matrix.endpoint.clone(),
            config.matrix.secret.clone(),
            http_client,
        );

        drop(config);

        info!("Starting task scheduler");
        mas_tasks::init(
            &pool,
            &mailer,
            conn,
            url_builder,
            shutdown.soft_shutdown_token(),
            shutdown.task_tracker(),
        )
        .await?;

        span.exit();

        shutdown.run().await;

        Ok(ExitCode::SUCCESS)
    }
}
