// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Sets up the logging output from the `telemetry.logging` configuration.

use std::io::IsTerminal as _;

use anyhow::Context as _;
use mas_config::{LogColor, LogFormat, LogOutput, LoggingConfig};
use mas_context::{EventFormatter, JsonEventFormatter};
use tracing_subscriber::{
    EnvFilter, Layer, Registry, filter::filter_fn, fmt::MakeWriter, layer::SubscriberExt as _,
    util::SubscriberInitExt as _,
};

/// A boxed [`Layer`] over the bare [`Registry`].
pub type BoxLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

/// Install the global subscriber, with the formatting layer and filter built
/// from the given configuration, alongside the given extra layers.
///
/// # Errors
///
/// Returns an error if the log filter could not be parsed, or if the global
/// subscriber could not be installed.
pub fn init(config: &LoggingConfig, extra_layers: Vec<BoxLayer>) -> anyhow::Result<()> {
    let fmt_layer = match config.output {
        LogOutput::Stderr => {
            let is_terminal = std::io::stderr().is_terminal();
            fmt_layer(config, std::io::stderr, is_terminal)
        }
        LogOutput::Stdout => {
            let is_terminal = std::io::stdout().is_terminal();
            fmt_layer(config, std::io::stdout, is_terminal)
        }
    };

    let filter_layer = build_env_filter(config)?;

    // Suppress the following warning from the Jaeger propagator:
    //   Invalid jaeger header format header_value=""
    let suppress_layer = filter_fn(|metadata| metadata.name() != "JaegerPropagator.InvalidHeader");

    let mut layers = extra_layers;
    layers.push(fmt_layer);

    Registry::default()
        .with(layers)
        .with(suppress_layer)
        .with(filter_layer)
        .try_init()
        .context("could not initialize logging")?;

    Ok(())
}

/// Build the formatting layer, writing synchronously to the given writer.
fn fmt_layer<W>(config: &LoggingConfig, writer: W, is_terminal: bool) -> BoxLayer
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let ansi = match config.color {
        LogColor::Auto => is_terminal,
        LogColor::Always => true,
        LogColor::Never => false,
    };

    match config.format {
        LogFormat::Text => Box::new(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .event_format(EventFormatter)
                .with_ansi(ansi),
        ),
        LogFormat::Json => Box::new(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .event_format(JsonEventFormatter),
        ),
    }
}

/// Build the [`EnvFilter`] from the configuration.
///
/// The `RUST_LOG` environment variable, when set, takes precedence over the
/// configured filter. If neither is set, it defaults to `info`.
fn build_env_filter(config: &LoggingConfig) -> anyhow::Result<EnvFilter> {
    if std::env::var(EnvFilter::DEFAULT_ENV).is_ok() {
        return EnvFilter::try_from_default_env()
            .context("could not parse the RUST_LOG environment variable");
    }

    let directive = config.filter.as_deref().unwrap_or("info");
    EnvFilter::try_new(directive)
        .with_context(|| format!("could not parse the configured log filter ({directive:?})"))
}
