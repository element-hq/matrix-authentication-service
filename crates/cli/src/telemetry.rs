// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

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
use opentelemetry_prometheus_text_exporter::PrometheusExporter;
use opentelemetry_sdk::{
    Resource,
    metrics::{ManualReader, SdkMeterProvider, periodic_reader_with_async_runtime::PeriodicReader},
    propagation::{BaggagePropagator, TraceContextPropagator},
    trace::{
        IdGenerator, Sampler, SdkTracerProvider, Tracer,
        span_processor_with_async_runtime::BatchSpanProcessor,
    },
};
use opentelemetry_semantic_conventions as semcov;

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
static PROMETHEUS_EXPORTER: OnceLock<PrometheusExporter> = OnceLock::new();

pub fn setup(config: &TelemetryConfig) -> anyhow::Result<()> {
    let propagator = propagator(&config.tracing.propagators);

    // The CORS filter needs to know what headers it should whitelist for
    // CORS-protected requests.
    mas_http::set_propagator(&propagator);
    opentelemetry::global::set_text_map_propagator(propagator);

    init_tracer(&config.tracing).context("Failed to configure traces exporter")?;
    init_meter(&config.metrics).context("Failed to configure metrics exporter")?;

    opentelemetry_instrumentation_process::init()
        .context("Failed to configure process instrumentation")?;
    opentelemetry_instrumentation_tokio::observe_current_runtime();

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

/// An [`IdGenerator`] which always returns an invalid trace ID and span ID
///
/// This is used when no exporter is being used, so that we don't log the trace
/// ID when we're not tracing.
#[derive(Debug, Clone, Copy)]
struct InvalidIdGenerator;
impl IdGenerator for InvalidIdGenerator {
    fn new_trace_id(&self) -> opentelemetry::TraceId {
        opentelemetry::TraceId::INVALID
    }
    fn new_span_id(&self) -> opentelemetry::SpanId {
        opentelemetry::SpanId::INVALID
    }
}

fn init_tracer(config: &TracingConfig) -> anyhow::Result<()> {
    let sample_rate = config.sample_rate.unwrap_or(1.0);

    // We sample traces based on the parent if we have one, and if not, we
    // sample a ratio based on the configured sample rate
    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(sample_rate)));

    let tracer_provider_builder = SdkTracerProvider::builder()
        .with_resource(resource())
        .with_sampler(sampler);

    let tracer_provider = match config.exporter {
        TracingExporterKind::None => tracer_provider_builder
            .with_id_generator(InvalidIdGenerator)
            .with_sampler(Sampler::AlwaysOff)
            .build(),

        TracingExporterKind::Stdout => {
            let exporter = opentelemetry_stdout::SpanExporter::default();
            tracer_provider_builder
                .with_simple_exporter(exporter)
                .build()
        }

        TracingExporterKind::Otlp => {
            let mut exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_http_client(mas_http::reqwest_client());
            if let Some(endpoint) = &config.endpoint {
                exporter = exporter.with_endpoint(endpoint.as_str());
            }
            let exporter = exporter
                .build()
                .context("Failed to configure OTLP trace exporter")?;

            let batch_processor =
                BatchSpanProcessor::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();

            tracer_provider_builder
                .with_span_processor(batch_processor)
                .build()
        }
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
    let response = if let Some(exporter) = PROMETHEUS_EXPORTER.get() {
        // We'll need some space for this, so we preallocate a bit
        let mut buffer = Vec::with_capacity(1024);

        if let Err(err) = exporter.export(&mut buffer) {
            tracing::error!(
                error = &err as &dyn std::error::Error,
                "Failed to export Prometheus metrics"
            );

            Response::builder()
                .status(500)
                .header(CONTENT_TYPE, "text/plain")
                .body(Full::new(Bytes::from_static(
                    b"Failed to export Prometheus metrics, see logs for details",
                )))
                .unwrap()
        } else {
            Response::builder()
                .status(200)
                .header(CONTENT_TYPE, "text/plain;version=1.0.0")
                .body(Full::new(Bytes::from(buffer)))
                .unwrap()
        }
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
    if PROMETHEUS_EXPORTER.get().is_none() {
        tracing::warn!(
            "A Prometheus resource was mounted on a listener, but the Prometheus exporter was not setup in the config"
        );
    }

    tower::service_fn(prometheus_service_fn as _)
}

fn prometheus_metric_reader() -> anyhow::Result<PrometheusExporter> {
    let exporter = PrometheusExporter::builder().without_scope_info().build();

    PROMETHEUS_EXPORTER
        .set(exporter.clone())
        .map_err(|_| anyhow::anyhow!("PROMETHEUS_EXPORTER was set twice"))?;

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
                // Use rustc version from build.rs, or "unknown" if not available
                option_env!("MAS_RUSTC_VERSION").unwrap_or("unknown"),
            ),
        ])
        .build()
}
