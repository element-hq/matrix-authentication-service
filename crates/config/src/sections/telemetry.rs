// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error as _};
use serde_with::skip_serializing_none;
use url::Url;

use super::ConfigurationSection;

fn sample_rate_example() -> f64 {
    0.5
}

/// Propagation format for incoming and outgoing requests
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Propagator {
    /// Propagate according to the W3C Trace Context specification
    TraceContext,

    /// Propagate according to the W3C Baggage specification
    Baggage,

    /// Propagate trace context with Jaeger compatible headers
    Jaeger,
}

#[allow(clippy::unnecessary_wraps)]
fn otlp_endpoint_default() -> Option<String> {
    Some("https://localhost:4318".to_owned())
}

/// Exporter to use when exporting traces
#[skip_serializing_none]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum TracingExporterKind {
    /// Don't export traces
    #[default]
    None,

    /// Export traces to the standard output. Only useful for debugging
    Stdout,

    /// Export traces to an OpenTelemetry protocol compatible endpoint
    Otlp,
}

/// Configuration related to exporting traces
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TracingConfig {
    /// Exporter to use when exporting traces
    #[serde(default)]
    pub exporter: TracingExporterKind,

    /// OTLP exporter: OTLP over HTTP compatible endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(url, default = "otlp_endpoint_default")]
    pub endpoint: Option<Url>,

    /// List of propagation formats to use for incoming and outgoing requests
    #[serde(default)]
    pub propagators: Vec<Propagator>,

    /// Sample rate for traces
    ///
    /// Defaults to `1.0` if not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = "sample_rate_example", range(min = 0.0, max = 1.0))]
    pub sample_rate: Option<f64>,
}

impl TracingConfig {
    /// Returns true if all fields are at their default values
    fn is_default(&self) -> bool {
        matches!(self.exporter, TracingExporterKind::None)
            && self.endpoint.is_none()
            && self.propagators.is_empty()
    }
}

/// Exporter to use when exporting metrics
#[skip_serializing_none]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum MetricsExporterKind {
    /// Don't export metrics
    #[default]
    None,

    /// Export metrics to stdout. Only useful for debugging
    Stdout,

    /// Export metrics to an OpenTelemetry protocol compatible endpoint
    Otlp,

    /// Export metrics via Prometheus. An HTTP listener with the `prometheus`
    /// resource must be setup to expose the Promethes metrics.
    Prometheus,
}

/// Configuration related to exporting metrics
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct MetricsConfig {
    /// Exporter to use when exporting metrics
    #[serde(default)]
    pub exporter: MetricsExporterKind,

    /// OTLP exporter: OTLP over HTTP compatible endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(url, default = "otlp_endpoint_default")]
    pub endpoint: Option<Url>,
}

impl MetricsConfig {
    /// Returns true if all fields are at their default values
    fn is_default(&self) -> bool {
        matches!(self.exporter, MetricsExporterKind::None) && self.endpoint.is_none()
    }
}

fn sentry_dsn_example() -> &'static str {
    "https://public@host:port/1"
}

fn sentry_environment_example() -> &'static str {
    "production"
}

/// Configuration related to the Sentry integration
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct SentryConfig {
    /// Sentry DSN
    #[schemars(url, example = "sentry_dsn_example")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsn: Option<String>,

    /// Environment to use when sending events to Sentry
    ///
    /// Defaults to `production` if not set.
    #[schemars(example = "sentry_environment_example")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,

    /// Sample rate for event submissions
    ///
    /// Defaults to `1.0` if not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = "sample_rate_example", range(min = 0.0, max = 1.0))]
    pub sample_rate: Option<f32>,

    /// Sample rate for tracing transactions
    ///
    /// Defaults to `0.0` if not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = "sample_rate_example", range(min = 0.0, max = 1.0))]
    pub traces_sample_rate: Option<f32>,
}

impl SentryConfig {
    /// Returns true if all fields are at their default values
    fn is_default(&self) -> bool {
        self.dsn.is_none()
    }
}

/// Configuration related to sending monitoring data
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TelemetryConfig {
    /// Configuration related to exporting traces
    #[serde(default, skip_serializing_if = "TracingConfig::is_default")]
    pub tracing: TracingConfig,

    /// Configuration related to exporting metrics
    #[serde(default, skip_serializing_if = "MetricsConfig::is_default")]
    pub metrics: MetricsConfig,

    /// Configuration related to the Sentry integration
    #[serde(default, skip_serializing_if = "SentryConfig::is_default")]
    pub sentry: SentryConfig,
}

impl TelemetryConfig {
    /// Returns true if all fields are at their default values
    pub(crate) fn is_default(&self) -> bool {
        self.tracing.is_default() && self.metrics.is_default() && self.sentry.is_default()
    }
}

impl ConfigurationSection for TelemetryConfig {
    const PATH: Option<&'static str> = Some("telemetry");

    fn validate(
        &self,
        _figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        if let Some(sample_rate) = self.sentry.sample_rate
            && !(0.0..=1.0).contains(&sample_rate)
        {
            return Err(figment::error::Error::custom(
                "Sentry sample rate must be between 0.0 and 1.0",
            )
            .with_path("sentry.sample_rate")
            .into());
        }

        if let Some(sample_rate) = self.sentry.traces_sample_rate
            && !(0.0..=1.0).contains(&sample_rate)
        {
            return Err(figment::error::Error::custom(
                "Sentry sample rate must be between 0.0 and 1.0",
            )
            .with_path("sentry.traces_sample_rate")
            .into());
        }

        if let Some(sample_rate) = self.tracing.sample_rate
            && !(0.0..=1.0).contains(&sample_rate)
        {
            return Err(figment::error::Error::custom(
                "Tracing sample rate must be between 0.0 and 1.0",
            )
            .with_path("tracing.sample_rate")
            .into());
        }

        Ok(())
    }
}
