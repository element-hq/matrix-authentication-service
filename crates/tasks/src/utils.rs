// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use apalis_core::{job::Job, request::JobRequest};
use mas_storage::job::JobWithSpanContext;
use mas_tower::{
    make_span_fn, DurationRecorderLayer, FnWrapper, IdentityLayer, InFlightCounterLayer,
    TraceLayer, KV,
};
use opentelemetry::{trace::SpanContext, Key, KeyValue};
use tracing::info_span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

const JOB_NAME: Key = Key::from_static_str("job.name");
const JOB_STATUS: Key = Key::from_static_str("job.status");

/// Represents a job that can may have a span context attached to it.
pub trait TracedJob: Job {
    /// Returns the span context for this job, if any.
    ///
    /// The default implementation returns `None`.
    fn span_context(&self) -> Option<SpanContext> {
        None
    }
}

/// Implements [`TracedJob`] for any job with the [`JobWithSpanContext`]
/// wrapper.
impl<J: Job> TracedJob for JobWithSpanContext<J> {
    fn span_context(&self) -> Option<SpanContext> {
        JobWithSpanContext::span_context(self)
    }
}

fn make_span_for_job_request<J: TracedJob>(req: &JobRequest<J>) -> tracing::Span {
    let span = info_span!(
        "job.run",
        "otel.kind" = "consumer",
        "otel.status_code" = tracing::field::Empty,
        "job.id" = %req.id(),
        "job.attempts" = req.attempts(),
        "job.name" = J::NAME,
    );

    if let Some(context) = req.inner().span_context() {
        span.add_link(context);
    }

    span
}

type TraceLayerForJob<J> =
    TraceLayer<FnWrapper<fn(&JobRequest<J>) -> tracing::Span>, KV<&'static str>, KV<&'static str>>;

pub(crate) fn trace_layer<J>() -> TraceLayerForJob<J>
where
    J: TracedJob,
{
    TraceLayer::new(make_span_fn(
        make_span_for_job_request::<J> as fn(&JobRequest<J>) -> tracing::Span,
    ))
    .on_response(KV("otel.status_code", "OK"))
    .on_error(KV("otel.status_code", "ERROR"))
}

type MetricsLayerForJob<J> = (
    IdentityLayer<JobRequest<J>>,
    DurationRecorderLayer<KeyValue, KeyValue, KeyValue>,
    InFlightCounterLayer<KeyValue>,
);

pub(crate) fn metrics_layer<J>() -> MetricsLayerForJob<J>
where
    J: Job,
{
    let duration_recorder = DurationRecorderLayer::new("job.run.duration")
        .on_request(JOB_NAME.string(J::NAME))
        .on_response(JOB_STATUS.string("success"))
        .on_error(JOB_STATUS.string("error"));
    let in_flight_counter =
        InFlightCounterLayer::new("job.run.active").on_request(JOB_NAME.string(J::NAME));

    (
        IdentityLayer::default(),
        duration_recorder,
        in_flight_counter,
    )
}
