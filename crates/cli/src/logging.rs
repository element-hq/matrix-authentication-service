// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Sets up the logging output from the `telemetry.logging` configuration.

use std::io::IsTerminal as _;

use anyhow::Context as _;
use mas_config::{LogColor, LogFormat, LogOutput, LoggingConfig};
use mas_context::{EventFormatter, JsonEventFormatter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, Layer, Registry, filter::filter_fn, layer::SubscriberExt as _,
    util::SubscriberInitExt as _,
};

/// A boxed [`Layer`] over the bare [`Registry`].
pub type BoxLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

/// A guard which must be kept alive for the lifetime of the program, so that
/// the non-blocking log writer flushes its buffer on shutdown.
#[must_use = "the worker guard must be kept alive for logs to be flushed"]
pub struct LoggingGuard {
    _worker_guard: WorkerGuard,
}

/// Install the global subscriber, with the formatting layer and filter built
/// from the given configuration, alongside the given extra layers.
///
/// # Errors
///
/// Returns an error if the log filter could not be parsed, or if the global
/// subscriber could not be installed.
pub fn init(config: &LoggingConfig, extra_layers: Vec<BoxLayer>) -> anyhow::Result<LoggingGuard> {
    let (writer, worker_guard, is_terminal) = match config.output {
        LogOutput::Stderr => {
            let output = std::io::stderr();
            let is_terminal = output.is_terminal();
            let (writer, guard) = tracing_appender::non_blocking(output);
            (writer, guard, is_terminal)
        }
        LogOutput::Stdout => {
            let output = std::io::stdout();
            let is_terminal = output.is_terminal();
            let (writer, guard) = tracing_appender::non_blocking(output);
            (writer, guard, is_terminal)
        }
    };

    let ansi = match config.color {
        LogColor::Auto => is_terminal,
        LogColor::Always => true,
        LogColor::Never => false,
    };

    let fmt_layer: BoxLayer = match config.format {
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

    Ok(LoggingGuard {
        _worker_guard: worker_guard,
    })
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
