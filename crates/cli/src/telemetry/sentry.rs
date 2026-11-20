// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{borrow::Cow, collections::BTreeMap, sync::Arc, time::Duration};

use mas_config::TelemetryConfig;
use mas_context::{LogContext, Requester};
use opentelemetry::trace::TraceContextExt as _;
use sentry::protocol::{Context, Event, TraceContext, User, Value};
use sentry_tracing::{BreadcrumbLayer, ErrorLayer, SpanLayer};
use tracing::{Level, Metadata, Span, Subscriber};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, filter_fn},
    registry::LookupSpan,
};

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
    fn create_transport_with_options(
        &self,
        options: sentry::TransportOptions,
    ) -> Arc<dyn sentry::Transport> {
        let transport = sentry::transports::ReqwestHttpTransportOptions::from(options)
            .with_client(self.client.clone())
            .build();

        Arc::new(transport)
    }
}

/// Initialize the Sentry client
///
/// The returned guard flushes the pending events when dropped.
pub fn init(config: &TelemetryConfig) -> sentry::ClientInitGuard {
    let config = &config.sentry;
    let sentry_tracing = config.traces_sample_rate.is_some();
    let mut options = sentry::ClientOptions::new()
        .transport(SentryTransportFactory::new())
        .release(crate::VERSION)
        .sample_rate(config.sample_rate.unwrap_or(1.0))
        .attach_stacktrace(true)
        // The prefixes are matched against function names, which requires the
        // symbol table to be kept in the binary
        .in_app_include(["mas_", "oauth2_types", "syn2mas"])
        .before_send(move |mut event| {
            set_fingerprint(&mut event);
            tag_job_fields(&mut event);
            add_requester(&mut event);
            link_trace(&mut event, &Span::current(), sentry_tracing);
            LogContext::maybe_with(|ctx| {
                set_transaction(&mut event, ctx);
                add_log_context(&mut event, ctx);
            });
            Some(event)
        });
    // Without a sampler or a rate, Sentry doesn't start transactions at all.
    // Only performance traces are sampled here; error events use `sample_rate`.
    if let Some(traces_sample_rate) = config.traces_sample_rate {
        options = options.traces_sampler(move |ctx| match ctx.operation() {
            // The ops set by `SentryHttpLayer` and by the `sentry.op` field of the
            // job span in `mas_tasks`. Every other root span, like the ones of the
            // worker loop, would otherwise be its own transaction.
            "http.server" | "queue.process" => ctx.sampled().map_or(traces_sample_rate, f32::from),
            _ => 0.0,
        });
    }
    if let Some(environment) = config.environment.clone() {
        options = options.environment(environment);
    }

    sentry::init((config.dsn.as_deref(), options))
}

/// Errors logged from a shared place, like the job runner, all have the same
/// stack trace. Group them by the log context they were logged in, and by the
/// GraphQL resolver they come from, on top of the default grouping.
///
/// Requests are left out: their tag is the HTTP method, which would split an
/// error shared by the handlers of several methods. `sentry-tower` attaches
/// the request to events through the scope, which is applied before
/// `before_send`.
fn set_fingerprint(event: &mut Event<'static>) {
    let mut fingerprint = vec![Cow::Borrowed("{{ default }}")];

    if event.request.is_none()
        && let Some(tag) = LogContext::maybe_with(|ctx| ctx.tag().clone())
    {
        fingerprint.push(tag);
    }

    if let Some(path) = event.tags.get("graphql.path") {
        fingerprint.push(Cow::Owned(path.clone()));
    }

    event.fingerprint = Cow::Owned(fingerprint);
}

/// Record the requester of the current log context on the event.
///
/// This runs in the task which captured the event, so the log context of the
/// request or job is available. Usernames are left out, as they are personal
/// data.
fn add_requester(event: &mut Event<'static>) {
    let Some(requester) = LogContext::maybe_with(|ctx| ctx.requester().cloned()).flatten() else {
        return;
    };

    match requester {
        Requester::User { id, .. } => {
            event.user.get_or_insert_with(|| User {
                id: Some(id.to_string()),
                ..User::default()
            });
            event.tags.insert("requester".to_owned(), "user".to_owned());
        }
        Requester::OAuth2Client { id } => {
            event
                .tags
                .insert("requester".to_owned(), "oauth2-client".to_owned());
            event
                .tags
                .insert("oauth2_client.id".to_owned(), id.to_string());
        }
        Requester::Homeserver => {
            event
                .tags
                .insert("requester".to_owned(), "homeserver".to_owned());
        }
    }
}

/// Link the event to the OpenTelemetry trace of the given span, so that it
/// can be looked up in the tracing backend.
///
/// With Sentry tracing enabled, the trace context of the event points to the
/// Sentry transaction, so the OpenTelemetry trace ID goes in a tag instead.
///
/// `before_send` runs while the tracing dispatcher handles the event, where
/// [`Span::current`] only resolves through the global dispatcher, not a scoped
/// one.
fn link_trace(event: &mut Event<'static>, span: &Span, sentry_tracing: bool) {
    let context = span.context();
    let span_context = context.span().span_context().clone();
    if !span_context.is_valid() {
        return;
    }

    if sentry_tracing {
        event.tags.insert(
            "otel.trace_id".to_owned(),
            span_context.trace_id().to_string(),
        );
    } else {
        let trace = TraceContext {
            trace_id: span_context.trace_id().to_bytes().into(),
            span_id: span_context.span_id().to_bytes().into(),
            ..TraceContext::default()
        };
        event.contexts.insert("trace".to_owned(), trace.into());
    }
}

/// Name the event after the matched route of the request, as its URL has
/// unbounded cardinality. `sentry-tower` names the transaction it starts, but
/// not the events captured during it.
fn set_transaction(event: &mut Event<'static>, ctx: &LogContext) {
    if event.transaction.is_none()
        && let Some(route) = ctx.route()
    {
        event.transaction = Some(route.to_owned());
    }
}

fn millis(duration: Duration) -> Value {
    Value::from(duration.as_secs_f64() * 1000.)
}

/// Record the tag and the statistics of the log context on the event.
fn add_log_context(event: &mut Event<'static>, ctx: &LogContext) {
    let stats = ctx.stats();
    let context = BTreeMap::from([
        ("tag".to_owned(), Value::from(ctx.tag().as_ref())),
        ("polls".to_owned(), Value::from(stats.polls)),
        ("cpu_time_ms".to_owned(), millis(stats.cpu_time)),
        ("db_time_ms".to_owned(), millis(stats.db_time)),
        ("db_queries".to_owned(), Value::from(stats.db_queries)),
        (
            "db_rows_fetched".to_owned(),
            Value::from(stats.db_rows_fetched),
        ),
        ("elapsed_ms".to_owned(), millis(stats.elapsed)),
    ]);
    event
        .contexts
        .insert("Log Context".to_owned(), Context::Other(context));
}

/// The fields of the job failure events logged by `mas_tasks` to copy into
/// tags, as Sentry only indexes tags.
const JOB_TAG_FIELDS: [&str; 3] = ["job.queue.name", "job.attempt", "job.outcome"];

/// Copy the job fields of the event into tags. `sentry-tracing` stores the
/// fields of the `tracing` event in the "Rust Tracing Fields" context.
fn tag_job_fields(event: &mut Event<'static>) {
    let Some(Context::Other(fields)) = event.contexts.get("Rust Tracing Fields") else {
        return;
    };

    for key in JOB_TAG_FIELDS {
        let value = match fields.get(key) {
            Some(Value::String(value)) => value.clone(),
            Some(Value::Number(value)) => value.to_string(),
            _ => continue,
        };
        event.tags.insert(key.to_owned(), value);
    }
}

/// The error behind a 5xx response is already reported where it is handled, so
/// the response log event only needs to be a breadcrumb.
fn is_http_response(metadata: &Metadata<'_>) -> bool {
    metadata.name() == "http.server.response"
}

fn is_breadcrumb(metadata: &Metadata<'_>) -> bool {
    metadata.is_event()
        && (is_http_response(metadata) || matches!(*metadata.level(), Level::WARN | Level::INFO))
}

fn is_error(metadata: &Metadata<'_>) -> bool {
    metadata.is_event() && *metadata.level() == Level::ERROR && !is_http_response(metadata)
}

/// Build the `tracing` layer which reports events and spans to Sentry
pub fn layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    // An error event takes the breadcrumbs recorded before it, so the
    // breadcrumb layer has to see an event first.
    SpanLayer::new()
        .with_filter(LevelFilter::INFO)
        .and_then(BreadcrumbLayer::new().with_filter(filter_fn(is_breadcrumb)))
        .and_then(ErrorLayer::new().with_filter(filter_fn(is_error)))
}

#[cfg(test)]
mod tests {
    use sentry::protocol::Level;
    use tracing_subscriber::{Registry, layer::SubscriberExt as _};

    use super::*;

    fn capture(f: impl FnOnce()) -> Vec<Event<'static>> {
        let subscriber = Registry::default().with(layer());
        sentry::test::with_captured_events(|| tracing::subscriber::with_default(subscriber, f))
    }

    fn breadcrumb_messages<'a>(event: &'a Event<'static>) -> Vec<&'a str> {
        event
            .breadcrumbs
            .iter()
            .filter_map(|breadcrumb| breadcrumb.message.as_deref())
            .collect()
    }

    #[test]
    fn test_link_trace() {
        use opentelemetry::trace::TracerProvider as _;

        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let subscriber = Registry::default()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));

        tracing::subscriber::with_default(subscriber, || {
            let mut event = Event::default();
            link_trace(&mut event, &Span::current(), false);
            link_trace(&mut event, &Span::current(), true);
            assert!(event.contexts.is_empty());
            assert!(event.tags.is_empty());

            let span = tracing::info_span!("test");
            let context = span.context();
            let span_context = context.span().span_context().clone();
            assert!(span_context.is_valid());

            link_trace(&mut event, &span, true);
            assert!(event.contexts.is_empty());
            assert_eq!(
                event.tags["otel.trace_id"],
                span_context.trace_id().to_string()
            );

            let mut event = Event::default();
            link_trace(&mut event, &span, false);
            assert!(event.tags.is_empty());
            let Some(Context::Trace(trace)) = event.contexts.get("trace") else {
                panic!("missing trace context");
            };
            assert_eq!(
                trace.trace_id.to_string(),
                span_context.trace_id().to_string()
            );
            assert_eq!(
                trace.span_id.to_string(),
                span_context.span_id().to_string()
            );
        });
    }

    #[test]
    fn test_set_transaction() {
        let ctx = LogContext::new("GET");
        let mut event = Event::default();
        set_transaction(&mut event, &ctx);
        assert_eq!(event.transaction, None);

        ctx.set_route("GET /users/{id}".to_owned());
        set_transaction(&mut event, &ctx);
        assert_eq!(event.transaction.as_deref(), Some("GET /users/{id}"));

        let mut event = Event {
            transaction: Some("custom".to_owned()),
            ..Event::default()
        };
        set_transaction(&mut event, &ctx);
        assert_eq!(event.transaction.as_deref(), Some("custom"));
    }

    #[test]
    fn test_add_log_context() {
        let ctx = LogContext::new("test");
        ctx.record_query_stats(3, Duration::from_millis(2));
        let mut event = Event::default();
        add_log_context(&mut event, &ctx);

        let Some(Context::Other(context)) = event.contexts.get("Log Context") else {
            panic!("missing log context");
        };
        assert_eq!(context["tag"], "test");
        assert_eq!(context["polls"], 0);
        assert_eq!(context["db_queries"], 1);
        assert_eq!(context["db_rows_fetched"], 3);
        assert_eq!(context["db_time_ms"], 2.0);
        assert!(context["cpu_time_ms"].is_f64());
        assert!(context["elapsed_ms"].is_f64());
    }

    #[test]
    fn test_event_filters() {
        let events = capture(|| {
            tracing::trace!("trace");
            tracing::debug!("debug");
            tracing::info!("info");
            tracing::warn!("warn");
            tracing::error!(name: "http.server.response", "response");
            tracing::error!("error");
        });

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.level, Level::Error);
        assert_eq!(event.message.as_deref(), Some("error"));
        assert_eq!(breadcrumb_messages(event), ["info", "warn", "response"]);
    }

    #[test]
    fn test_tag_job_fields() {
        let events = capture(|| {
            tracing::error!(
                job.id = "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                job.queue.name = "send-email",
                job.attempt = 2,
                job.outcome = "retry",
                "Job failed, will retry"
            );
        });

        let mut event = events.into_iter().next().unwrap();
        assert!(event.tags.is_empty());
        tag_job_fields(&mut event);
        assert_eq!(event.tags["job.queue.name"], "send-email");
        assert_eq!(event.tags["job.attempt"], "2");
        assert_eq!(event.tags["job.outcome"], "retry");
        assert!(!event.tags.contains_key("job.id"));
    }
}
