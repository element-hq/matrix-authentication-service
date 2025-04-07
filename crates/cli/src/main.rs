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
    EnvFilter, Layer, Registry, filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt,
};

mod app_state;
mod commands;
mod lifecycle;
mod server;
mod sync;
mod telemetry;
mod util;

/// The application version, as reported by `git describe` at build time
static VERSION: &str = env!("VERGEN_GIT_DESCRIBE");

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

fn main() -> anyhow::Result<ExitCode> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    #[cfg(tokio_unstable)]
    builder
        .enable_metrics_poll_time_histogram()
        .metrics_poll_time_histogram_configuration(tokio::runtime::HistogramConfiguration::log(
            tokio::runtime::LogHistogram::default(),
        ));

    let runtime = builder.build()?;

    runtime.block_on(async_main())
}

async fn async_main() -> anyhow::Result<ExitCode> {
    // We're splitting the "fallible" part of main in another function to have a
    // chance to shutdown the telemetry exporters regardless of if there was an
    // error or not
    let res = try_main().await;
    if let Err(err) = self::telemetry::shutdown() {
        eprintln!("Failed to shutdown telemetry exporters: {err}");
    }
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

    let telemetry_config =
        TelemetryConfig::extract(&figment).context("Failed to load telemetry config")?;

    // Setup Sentry
    let sentry = sentry::init((
        telemetry_config.sentry.dsn.as_deref(),
        sentry::ClientOptions {
            transport: Some(Arc::new(SentryTransportFactory::new())),
            environment: telemetry_config.sentry.environment.clone().map(Into::into),
            release: Some(VERSION.into()),
            sample_rate: telemetry_config.sentry.sample_rate.unwrap_or(1.0),
            traces_sample_rate: telemetry_config.sentry.traces_sample_rate.unwrap_or(0.0),
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
    self::telemetry::setup(&telemetry_config).context("failed to setup OpenTelemetry")?;

    let telemetry_layer = self::telemetry::TRACER.get().map(|tracer| {
        tracing_opentelemetry::layer()
            .with_tracer(tracer.clone())
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
