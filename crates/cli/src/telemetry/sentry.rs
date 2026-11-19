// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{borrow::Cow, sync::Arc};

use mas_config::TelemetryConfig;
use mas_context::{LogContext, Requester};
use sentry::protocol::{Event, User};
use sentry_tracing::{BreadcrumbLayer, ErrorLayer, SpanLayer};
use tracing::{Level, Metadata, Subscriber};
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
    let mut options = sentry::ClientOptions::new()
        .transport(SentryTransportFactory::new())
        .release(crate::VERSION)
        .sample_rate(config.sample_rate.unwrap_or(1.0))
        .attach_stacktrace(true)
        // The prefixes are matched against function names, which requires the
        // symbol table to be kept in the binary
        .in_app_include(["mas_", "oauth2_types", "syn2mas"])
        .before_send(|mut event| {
            set_fingerprint(&mut event);
            add_requester(&mut event);
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
}
