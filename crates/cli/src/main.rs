// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

#![allow(clippy::module_name_repetitions)]

use std::{io::IsTerminal, process::ExitCode, sync::Arc};

use anyhow::Context;
use clap::Parser;
use mas_config::{ConfigurationSection, TelemetryConfig};
use sentry_tracing::EventFilter;
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};

mod app_state;
mod commands;
mod server;
mod shutdown;
mod sync;
mod telemetry;
mod util;

#[derive(Debug)]
struct SentryTransportFactory {
    client: reqwest::Client,
}

impl SentryTransportFactory {
    fn new() -> Self {
        Self {
            client: mas_http::reqwest_client(),
        }
    }
}

impl sentry::TransportFactory for SentryTransportFactory {
    fn create_transport(&self, options: &sentry::ClientOptions) -> Arc<dyn sentry::Transport> {
        let transport =
            sentry::transports::ReqwestHttpTransport::with_client(options, self.client.clone());

        Arc::new(transport)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    // We're splitting the "fallible" part of main in another function to have a
    // chance to shutdown the telemetry exporters regardless of if there was an
    // error or not
    let res = try_main().await;
    self::telemetry::shutdown();
    res
}

async fn try_main() -> anyhow::Result<ExitCode> {
    // Load environment variables from .env files
    // We keep the path to log it afterwards
    let dotenv_path: Result<Option<_>, _> = dotenvy::dotenv()
        .map(Some)
        // Display the error if it is something other than the .env file not existing
        .or_else(|e| if e.not_found() { Ok(None) } else { Err(e) });

    // Setup logging
    // This writes logs to stderr
    let output = std::io::stderr();
    let with_ansi = output.is_terminal();
    let (log_writer, _guard) = tracing_appender::non_blocking(output);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(log_writer)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(with_ansi);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .context("could not setup logging filter")?;

    // Setup the rustls crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("could not install the AWS LC crypto provider"))?;

    // Parse the CLI arguments
    let opts = self::commands::Options::parse();

    // Load the base configuration files
    let figment = opts.figment();

    // Telemetry config could fail to load, but that's probably OK, since the whole
    // config will be loaded afterwards, and crash if there is a problem.
    // Falling back to default.
    let telemetry_config = TelemetryConfig::extract(&figment).unwrap_or_default();

    // Setup Sentry
    let sentry = sentry::init((
        telemetry_config.sentry.dsn.as_deref(),
        sentry::ClientOptions {
            transport: Some(Arc::new(SentryTransportFactory::new())),
            traces_sample_rate: 1.0,
            auto_session_tracking: true,
            session_mode: sentry::SessionMode::Request,
            ..Default::default()
        },
    ));

    let sentry_layer = sentry.is_enabled().then(|| {
        sentry_tracing::layer().event_filter(|md| {
            // All the spans in the handlers module send their data to Sentry themselves, so
            // we only create breadcrumbs for them, instead of full events
            if md.target().starts_with("mas_handlers::") {
                EventFilter::Breadcrumb
            } else {
                sentry_tracing::default_event_filter(md)
            }
        })
    });

    // Setup OpenTelemetry tracing and metrics
    let tracer = telemetry::setup(&telemetry_config).context("failed to setup OpenTelemetry")?;

    let telemetry_layer = tracer.map(|tracer| {
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_tracked_inactivity(false)
            .with_filter(LevelFilter::INFO)
    });

    let subscriber = Registry::default()
        .with(sentry_layer)
        .with(telemetry_layer)
        .with(filter_layer)
        .with(fmt_layer);
    subscriber
        .try_init()
        .context("could not initialize logging")?;

    // Log about the .env loading
    match dotenv_path {
        Ok(Some(path)) => tracing::info!(?path, "Loaded environment variables from .env file"),
        Ok(None) => {}
        Err(e) => tracing::warn!(?e, "Failed to load .env file"),
    }

    // And run the command
    tracing::trace!(?opts, "Running command");
    opts.run(&figment).await
}
