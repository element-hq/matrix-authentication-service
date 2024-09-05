// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
pub use hyper_util::client::legacy::Client;
use hyper_util::{
    client::legacy::connect::{
        dns::{GaiResolver, Name},
        HttpConnector,
    },
    rt::TokioExecutor,
};
use mas_tower::{
    DurationRecorderLayer, DurationRecorderService, FnWrapper, InFlightCounterLayer,
    InFlightCounterService, TraceLayer, TraceService,
};
use opentelemetry_semantic_conventions::trace::SERVER_ADDRESS;
use tower::Layer;
use tracing::Span;

pub type UntracedClient<B> = Client<UntracedConnector, B>;
pub type TracedClient<B> = Client<TracedConnector, B>;

/// Create a basic Hyper HTTP & HTTPS client without any tracing
#[must_use]
pub fn make_untraced_client<B>() -> UntracedClient<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
{
    let https = make_untraced_connector();
    Client::builder(TokioExecutor::new()).build(https)
}

pub type TraceResolver<S> =
    InFlightCounterService<DurationRecorderService<TraceService<S, FnWrapper<fn(&Name) -> Span>>>>;
pub type UntracedConnector = HttpsConnector<HttpConnector<GaiResolver>>;
pub type TracedConnector = HttpsConnector<HttpConnector<TraceResolver<GaiResolver>>>;

/// Create a traced HTTP and HTTPS connector
#[must_use]
pub fn make_traced_connector() -> TracedConnector
where
{
    let in_flight_counter = InFlightCounterLayer::new("dns.resolve.active_requests");
    let duration_recorder = DurationRecorderLayer::new("dns.resolve.duration");
    let trace_layer = TraceLayer::from_fn(
        (|request: &Name| {
            tracing::info_span!(
                "dns.lookup",
                "otel.kind" = "client",
                { SERVER_ADDRESS } = %request,

            )
        }) as fn(&Name) -> Span,
    );

    let resolver = (in_flight_counter, duration_recorder, trace_layer).layer(GaiResolver::new());

    let tls_config = rustls_platform_verifier::tls_config();
    make_connector(resolver, tls_config)
}

fn make_untraced_connector() -> UntracedConnector
where
{
    let resolver = GaiResolver::new();
    let tls_config = rustls_platform_verifier::tls_config();
    make_connector(resolver, tls_config)
}

fn make_connector<R>(
    resolver: R,
    tls_config: rustls::ClientConfig,
) -> HttpsConnector<HttpConnector<R>> {
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);

    HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http)
}
