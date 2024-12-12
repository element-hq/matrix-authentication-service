// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{
    sync::{LazyLock, OnceLock},
    time::Duration,
};

use anyhow::Context as _;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{header::CONTENT_TYPE, Response};
use mas_config::{
    MetricsConfig, MetricsExporterKind, Propagator, TelemetryConfig, TracingConfig,
    TracingExporterKind,
};
use opentelemetry::{
    metrics::Meter,
    propagation::{TextMapCompositePropagator, TextMapPropagator},
    trace::TracerProvider as _,
    InstrumentationScope, KeyValue,
};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_prometheus::PrometheusExporter;
use opentelemetry_sdk::{
    metrics::{ManualReader, PeriodicReader, SdkMeterProvider},
    propagation::{BaggagePropagator, TraceContextPropagator},
    trace::{Sampler, Tracer, TracerProvider},
    Resource,
};
use opentelemetry_semantic_conventions as semcov;
use prometheus::Registry;
use url::Url;

static SCOPE: LazyLock<InstrumentationScope> = LazyLock::new(|| {
    InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(semcov::SCHEMA_URL)
        .build()
});

pub static METER: LazyLock<Meter> =
    LazyLock::new(|| opentelemetry::global::meter_with_scope(SCOPE.clone()));

pub static TRACER: OnceLock<Tracer> = OnceLock::new();
static METER_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();
static PROMETHEUS_REGISTRY: OnceLock<Registry> = OnceLock::new();

pub fn setup(config: &TelemetryConfig) -> anyhow::Result<()> {
    let propagator = propagator(&config.tracing.propagators);

    // The CORS filter needs to know what headers it should whitelist for
    // CORS-protected requests.
    mas_http::set_propagator(&propagator);
    opentelemetry::global::set_text_map_propagator(propagator);

    init_tracer(&config.tracing).context("Failed to configure traces exporter")?;
    init_meter(&config.metrics).context("Failed to configure metrics exporter")?;

    Ok(())
}

pub fn shutdown() {
    opentelemetry::global::shutdown_tracer_provider();

    if let Some(meter_provider) = METER_PROVIDER.get() {
        meter_provider.shutdown().unwrap();
    }
}

fn match_propagator(propagator: Propagator) -> Box<dyn TextMapPropagator + Send + Sync> {
    use Propagator as P;
    match propagator {
        P::TraceContext => Box::new(TraceContextPropagator::new()),
        P::Baggage => Box::new(BaggagePropagator::new()),
        P::Jaeger => Box::new(opentelemetry_jaeger_propagator::Propagator::new()),
    }
}

fn propagator(propagators: &[Propagator]) -> impl TextMapPropagator {
    let propagators = propagators.iter().copied().map(match_propagator).collect();

    TextMapCompositePropagator::new(propagators)
}

fn stdout_tracer_provider() -> TracerProvider {
    let exporter = opentelemetry_stdout::SpanExporter::default();
    TracerProvider::builder()
        .with_simple_exporter(exporter)
        .build()
}

fn otlp_tracer_provider(endpoint: Option<&Url>) -> anyhow::Result<TracerProvider> {
    let mut exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_http_client(mas_http::reqwest_client());
    if let Some(endpoint) = endpoint {
        exporter = exporter.with_endpoint(endpoint.to_string());
    }
    let exporter = exporter
        .build()
        .context("Failed to configure OTLP trace exporter")?;

    let tracer_provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(resource())
        .with_sampler(Sampler::AlwaysOn)
        .build();

    Ok(tracer_provider)
}

fn init_tracer(config: &TracingConfig) -> anyhow::Result<()> {
    let tracer_provider = match config.exporter {
        TracingExporterKind::None => return Ok(()),
        TracingExporterKind::Stdout => stdout_tracer_provider(),
        TracingExporterKind::Otlp => otlp_tracer_provider(config.endpoint.as_ref())?,
    };

    let tracer = tracer_provider.tracer_with_scope(SCOPE.clone());
    TRACER
        .set(tracer)
        .map_err(|_| anyhow::anyhow!("TRACER was set twice"))?;

    opentelemetry::global::set_tracer_provider(tracer_provider);

    Ok(())
}

fn otlp_metric_reader(endpoint: Option<&url::Url>) -> anyhow::Result<PeriodicReader> {
    let mut exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_http_client(mas_http::reqwest_client());
    if let Some(endpoint) = endpoint {
        exporter = exporter.with_endpoint(endpoint.to_string());
    }
    let exporter = exporter
        .build()
        .context("Failed to configure OTLP metric exporter")?;

    let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();
    Ok(reader)
}

fn stdout_metric_reader() -> PeriodicReader {
    let exporter = opentelemetry_stdout::MetricExporter::builder().build();
    PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio).build()
}

type PromServiceFuture =
    std::future::Ready<Result<Response<Full<Bytes>>, std::convert::Infallible>>;

#[allow(clippy::needless_pass_by_value)]
fn prometheus_service_fn<T>(_req: T) -> PromServiceFuture {
    use prometheus::{Encoder, TextEncoder};

    let response = if let Some(registry) = PROMETHEUS_REGISTRY.get() {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = registry.gather();

        // That shouldn't panic, unless we're constructing invalid labels
        encoder.encode(&metric_families, &mut buffer).unwrap();

        Response::builder()
            .status(200)
            .header(CONTENT_TYPE, encoder.format_type())
            .body(Full::new(Bytes::from(buffer)))
            .unwrap()
    } else {
        Response::builder()
            .status(500)
            .header(CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(
                b"Prometheus exporter was not enabled in config",
            )))
            .unwrap()
    };

    std::future::ready(Ok(response))
}

pub fn prometheus_service<T>() -> tower::util::ServiceFn<fn(T) -> PromServiceFuture> {
    if PROMETHEUS_REGISTRY.get().is_none() {
        tracing::warn!("A Prometheus resource was mounted on a listener, but the Prometheus exporter was not setup in the config");
    }

    tower::service_fn(prometheus_service_fn as _)
}

fn prometheus_metric_reader() -> anyhow::Result<PrometheusExporter> {
    let registry = Registry::new();

    PROMETHEUS_REGISTRY
        .set(registry.clone())
        .map_err(|_| anyhow::anyhow!("PROMETHEUS_REGISTRY was set twice"))?;

    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry)
        .without_scope_info()
        .build()?;

    Ok(exporter)
}

fn init_meter(config: &MetricsConfig) -> anyhow::Result<()> {
    let meter_provider_builder = SdkMeterProvider::builder();
    let meter_provider_builder = match config.exporter {
        MetricsExporterKind::None => meter_provider_builder.with_reader(ManualReader::default()),
        MetricsExporterKind::Stdout => meter_provider_builder.with_reader(stdout_metric_reader()),
        MetricsExporterKind::Otlp => {
            meter_provider_builder.with_reader(otlp_metric_reader(config.endpoint.as_ref())?)
        }
        MetricsExporterKind::Prometheus => {
            meter_provider_builder.with_reader(prometheus_metric_reader()?)
        }
    };

    let meter_provider = meter_provider_builder.with_resource(resource()).build();

    METER_PROVIDER
        .set(meter_provider.clone())
        .map_err(|_| anyhow::anyhow!("METER_PROVIDER was set twice"))?;
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    Ok(())
}

fn resource() -> Resource {
    let resource = Resource::new([
        KeyValue::new(semcov::resource::SERVICE_NAME, env!("CARGO_PKG_NAME")),
        KeyValue::new(semcov::resource::SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
    ]);

    let detected = Resource::from_detectors(
        Duration::from_secs(5),
        vec![
            Box::new(opentelemetry_sdk::resource::EnvResourceDetector::new()),
            Box::new(opentelemetry_resource_detectors::OsResourceDetector),
            Box::new(opentelemetry_resource_detectors::ProcessResourceDetector),
            Box::new(opentelemetry_sdk::resource::TelemetryResourceDetector),
        ],
    );

    resource.merge(&detected)
}
