// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod tokio;

use std::sync::{LazyLock, OnceLock};

use anyhow::Context as _;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, header::CONTENT_TYPE};
use mas_config::{
    MetricsConfig, MetricsExporterKind, Propagator, TelemetryConfig, TracingConfig,
    TracingExporterKind,
};
use opentelemetry::{
    InstrumentationScope, KeyValue,
    metrics::Meter,
    propagation::{TextMapCompositePropagator, TextMapPropagator},
    trace::TracerProvider as _,
};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_prometheus::PrometheusExporter;
use opentelemetry_sdk::{
    Resource,
    metrics::{ManualReader, SdkMeterProvider, periodic_reader_with_async_runtime::PeriodicReader},
    propagation::{BaggagePropagator, TraceContextPropagator},
    trace::{
        Sampler, SdkTracerProvider, Tracer, span_processor_with_async_runtime::BatchSpanProcessor,
    },
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
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();
static PROMETHEUS_REGISTRY: OnceLock<Registry> = OnceLock::new();

pub fn setup(config: &TelemetryConfig) -> anyhow::Result<()> {
    let propagator = propagator(&config.tracing.propagators);

    // The CORS filter needs to know what headers it should whitelist for
    // CORS-protected requests.
    mas_http::set_propagator(&propagator);
    opentelemetry::global::set_text_map_propagator(propagator);

    init_tracer(&config.tracing).context("Failed to configure traces exporter")?;
    init_meter(&config.metrics).context("Failed to configure metrics exporter")?;

    let handle = ::tokio::runtime::Handle::current();
    self::tokio::observe(handle.metrics());

    Ok(())
}

pub fn shutdown() -> opentelemetry_sdk::error::OTelSdkResult {
    if let Some(tracer_provider) = TRACER_PROVIDER.get() {
        tracer_provider.shutdown()?;
    }

    if let Some(meter_provider) = METER_PROVIDER.get() {
        meter_provider.shutdown()?;
    }

    Ok(())
}

fn match_propagator(propagator: Propagator) -> Box<dyn TextMapPropagator + Send + Sync> {
    use Propagator as P;
    match propagator {
        P::TraceContext => Box::new(TraceContextPropagator::new()),
        P::Baggage => Box::new(BaggagePropagator::new()),
        P::Jaeger => Box::new(opentelemetry_jaeger_propagator::Propagator::new()),
    }
}

fn propagator(propagators: &[Propagator]) -> TextMapCompositePropagator {
    let propagators = propagators.iter().copied().map(match_propagator).collect();

    TextMapCompositePropagator::new(propagators)
}

fn stdout_tracer_provider() -> SdkTracerProvider {
    let exporter = opentelemetry_stdout::SpanExporter::default();
    SdkTracerProvider::builder()
        .with_simple_exporter(exporter)
        .build()
}

fn otlp_tracer_provider(endpoint: Option<&Url>) -> anyhow::Result<SdkTracerProvider> {
    let mut exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_http_client(mas_http::reqwest_client());
    if let Some(endpoint) = endpoint {
        exporter = exporter.with_endpoint(endpoint.to_string());
    }
    let exporter = exporter
        .build()
        .context("Failed to configure OTLP trace exporter")?;

    let batch_processor =
        BatchSpanProcessor::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();

    let tracer_provider = SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
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
    TRACER_PROVIDER
        .set(tracer_provider.clone())
        .map_err(|_| anyhow::anyhow!("TRACER_PROVIDER was set twice"))?;

    let tracer = tracer_provider.tracer_with_scope(SCOPE.clone());
    TRACER
        .set(tracer)
        .map_err(|_| anyhow::anyhow!("TRACER was set twice"))?;

    opentelemetry::global::set_tracer_provider(tracer_provider);

    Ok(())
}

fn otlp_metric_reader(
    endpoint: Option<&url::Url>,
) -> anyhow::Result<PeriodicReader<opentelemetry_otlp::MetricExporter>> {
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

fn stdout_metric_reader() -> PeriodicReader<opentelemetry_stdout::MetricExporter> {
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
        tracing::warn!(
            "A Prometheus resource was mounted on a listener, but the Prometheus exporter was not setup in the config"
        );
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
    Resource::builder()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_detectors(&[
            Box::new(opentelemetry_resource_detectors::HostResourceDetector::default()),
            Box::new(opentelemetry_resource_detectors::OsResourceDetector),
            Box::new(opentelemetry_resource_detectors::ProcessResourceDetector),
        ])
        .with_attributes([
            KeyValue::new(semcov::resource::SERVICE_VERSION, crate::VERSION),
            KeyValue::new(semcov::resource::PROCESS_RUNTIME_NAME, "rust"),
            KeyValue::new(
                semcov::resource::PROCESS_RUNTIME_VERSION,
                env!("VERGEN_RUSTC_SEMVER"),
            ),
        ])
        .build()
}
