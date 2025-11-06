// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    str::FromStr,
    sync::{Arc, LazyLock},
    time::Duration,
};

use futures_util::FutureExt as _;
use headers::{ContentLength, HeaderMapExt as _, UserAgent};
use hyper_util::client::legacy::connect::{
    HttpInfo,
    dns::{GaiResolver, Name},
};
use opentelemetry::{
    KeyValue,
    metrics::{Histogram, UpDownCounter},
};
use opentelemetry_http::HeaderInjector;
use opentelemetry_semantic_conventions::{
    attribute::{HTTP_REQUEST_BODY_SIZE, HTTP_RESPONSE_BODY_SIZE},
    metric::{HTTP_CLIENT_ACTIVE_REQUESTS, HTTP_CLIENT_REQUEST_DURATION},
    trace::{
        ERROR_TYPE, HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, NETWORK_LOCAL_ADDRESS,
        NETWORK_LOCAL_PORT, NETWORK_PEER_ADDRESS, NETWORK_PEER_PORT, NETWORK_TRANSPORT,
        NETWORK_TYPE, SERVER_ADDRESS, SERVER_PORT, URL_FULL, URL_SCHEME, USER_AGENT_ORIGINAL,
    },
};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::time::Instant;
use tower::{BoxError, Service as _};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::METER;

static USER_AGENT: &str = concat!("matrix-authentication-service/", env!("CARGO_PKG_VERSION"));

static HTTP_REQUESTS_DURATION_HISTOGRAM: LazyLock<Histogram<u64>> = LazyLock::new(|| {
    METER
        .u64_histogram(HTTP_CLIENT_REQUEST_DURATION)
        .with_unit("ms")
        .with_description("Duration of HTTP client requests")
        .build()
});

static HTTP_REQUESTS_IN_FLIGHT: LazyLock<UpDownCounter<i64>> = LazyLock::new(|| {
    METER
        .i64_up_down_counter(HTTP_CLIENT_ACTIVE_REQUESTS)
        .with_unit("{requests}")
        .with_description("Number of HTTP client requests in flight")
        .build()
});

struct TracingResolver {
    inner: GaiResolver,
}

impl TracingResolver {
    fn new() -> Self {
        let inner = GaiResolver::new();
        Self { inner }
    }
}

impl reqwest::dns::Resolve for TracingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let span = tracing::info_span!("dns.resolve", name = name.as_str());
        let inner = &mut self.inner.clone();
        Box::pin(
            inner
                .call(Name::from_str(name.as_str()).unwrap())
                .map(|result| {
                    result
                        .map(|addrs| -> reqwest::dns::Addrs { Box::new(addrs) })
                        .map_err(|err| -> BoxError { Box::new(err) })
                })
                .instrument(span),
        )
    }
}

/// Create a new [`reqwest::Client`] with sane parameters
///
/// # Panics
///
/// Panics if the client fails to build, which should never happen
#[must_use]
pub fn client() -> reqwest::Client {
    // TODO: can/should we limit in-flight requests?

    // The explicit typing here is because `use_preconfigured_tls` accepts
    // `Any`, but wants a `ClientConfig` under the hood. This helps us detect
    // breaking changes in the rustls-platform-verifier API.
    let tls_config: rustls::ClientConfig =
        rustls::ClientConfig::with_platform_verifier().expect("failed to create TLS config");

    reqwest::Client::builder()
        .dns_resolver(Arc::new(TracingResolver::new()))
        .use_preconfigured_tls(tls_config)
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(30))
        .build()
        .expect("failed to create HTTP client")
}

async fn send_traced(
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, reqwest::Error> {
    let start = Instant::now();
    let (client, request) = request.build_split();
    let mut request = request?;

    let headers = request.headers();
    let server_address = request.url().host_str().map(ToOwned::to_owned);
    let server_port = request.url().port_or_known_default();
    let scheme = request.url().scheme().to_owned();
    let user_agent = headers
        .typed_get::<UserAgent>()
        .map(tracing::field::display);
    let content_length = headers.typed_get().map(|ContentLength(len)| len);
    let method = request.method().to_string();

    // Create a new span for the request
    let span = tracing::info_span!(
        "http.client.request",
        "otel.kind" = "client",
        "otel.status_code" = tracing::field::Empty,
        { HTTP_REQUEST_METHOD } = method,
        { URL_FULL } = %request.url(),
        { HTTP_RESPONSE_STATUS_CODE } = tracing::field::Empty,
        { SERVER_ADDRESS } = server_address,
        { SERVER_PORT } = server_port,
        { HTTP_REQUEST_BODY_SIZE } = content_length,
        { HTTP_RESPONSE_BODY_SIZE } = tracing::field::Empty,
        { NETWORK_TRANSPORT } = "tcp",
        { NETWORK_TYPE } = tracing::field::Empty,
        { NETWORK_LOCAL_ADDRESS } = tracing::field::Empty,
        { NETWORK_LOCAL_PORT } = tracing::field::Empty,
        { NETWORK_PEER_ADDRESS } = tracing::field::Empty,
        { NETWORK_PEER_PORT } = tracing::field::Empty,
        { USER_AGENT_ORIGINAL } = user_agent,
        "rust.error" = tracing::field::Empty,
    );

    // Inject the span context into the request headers
    let context = span.context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        let mut injector = HeaderInjector(request.headers_mut());
        propagator.inject_context(&context, &mut injector);
    });

    let mut metrics_labels = vec![
        KeyValue::new(HTTP_REQUEST_METHOD, method.clone()),
        KeyValue::new(URL_SCHEME, scheme),
    ];

    if let Some(server_address) = server_address {
        metrics_labels.push(KeyValue::new(SERVER_ADDRESS, server_address));
    }

    if let Some(server_port) = server_port {
        metrics_labels.push(KeyValue::new(SERVER_PORT, i64::from(server_port)));
    }

    HTTP_REQUESTS_IN_FLIGHT.add(1, &metrics_labels);
    async move {
        let span = tracing::Span::current();
        let result = client.execute(request).await;

        // XXX: We *could* loose this if the future is dropped before this, but let's
        // not worry about it for now. Ideally we would use a `Drop` guard to decrement
        // the counter
        HTTP_REQUESTS_IN_FLIGHT.add(-1, &metrics_labels);

        let duration = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let result = match result {
            Ok(response) => {
                span.record("otel.status_code", "OK");
                span.record(HTTP_RESPONSE_STATUS_CODE, response.status().as_u16());

                if let Some(ContentLength(content_length)) = response.headers().typed_get() {
                    span.record(HTTP_RESPONSE_BODY_SIZE, content_length);
                }

                if let Some(http_info) = response.extensions().get::<HttpInfo>() {
                    let local = http_info.local_addr();
                    let peer = http_info.remote_addr();
                    let family = if local.is_ipv4() { "ipv4" } else { "ipv6" };
                    span.record(NETWORK_TYPE, family);
                    span.record(NETWORK_LOCAL_ADDRESS, local.ip().to_string());
                    span.record(NETWORK_LOCAL_PORT, local.port());
                    span.record(NETWORK_PEER_ADDRESS, peer.ip().to_string());
                    span.record(NETWORK_PEER_PORT, peer.port());
                } else {
                    tracing::warn!("No HttpInfo injected in response extensions");
                }

                metrics_labels.push(KeyValue::new(
                    HTTP_RESPONSE_STATUS_CODE,
                    i64::from(response.status().as_u16()),
                ));

                Ok(response)
            }
            Err(err) => {
                span.record("otel.status_code", "ERROR");
                span.record("rust.error", &err as &dyn std::error::Error);

                metrics_labels.push(KeyValue::new(ERROR_TYPE, "NO_RESPONSE"));

                Err(err)
            }
        };

        HTTP_REQUESTS_DURATION_HISTOGRAM.record(duration, &metrics_labels);

        result
    }
    .instrument(span)
    .await
}

/// An extension trait implemented for [`reqwest::RequestBuilder`] to send a
/// request with a tracing span, and span context propagated.
pub trait RequestBuilderExt {
    /// Send the request with a tracing span, and span context propagated.
    fn send_traced(self) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> + Send;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn send_traced(self) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> + Send {
        send_traced(self)
    }
}
