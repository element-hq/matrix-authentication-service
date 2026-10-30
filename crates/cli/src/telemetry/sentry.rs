// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use mas_config::TelemetryConfig;
use sentry_tracing::EventFilter;
use tracing::Subscriber;
use tracing_subscriber::registry::LookupSpan;

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
        .sample_rate(config.sample_rate.unwrap_or(1.0));
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

/// Build the `tracing` layer which reports events and spans to Sentry
pub fn layer<S>() -> sentry_tracing::SentryLayer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    sentry_tracing::layer().event_filter(|md| {
        // By default, Sentry records all events as breadcrumbs, except errors.
        //
        // Because we're emitting error events for 5xx responses, we need to exclude
        // them and also record them as breadcrumbs.
        if md.name() == "http.server.response" {
            EventFilter::Breadcrumb
        } else {
            sentry_tracing::default_event_filter(md)
        }
    })
}
