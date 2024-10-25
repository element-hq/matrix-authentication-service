// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{future::Future, str::FromStr, sync::Arc, time::Duration};

use futures_util::FutureExt as _;
use headers::{ContentLength, HeaderMapExt as _, Host, UserAgent};
use hyper_util::client::legacy::connect::{
    dns::{GaiResolver, Name},
    HttpInfo,
};
use opentelemetry_http::HeaderInjector;
use opentelemetry_semantic_conventions::{
    attribute::{HTTP_REQUEST_BODY_SIZE, HTTP_RESPONSE_BODY_SIZE},
    trace::{
        CLIENT_ADDRESS, CLIENT_PORT, HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE,
        NETWORK_TRANSPORT, NETWORK_TYPE, SERVER_ADDRESS, SERVER_PORT, URL_FULL,
        USER_AGENT_ORIGINAL,
    },
};
use tower::{BoxError, Service as _};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

static USER_AGENT: &str = concat!("matrix-authentication-service/", env!("CARGO_PKG_VERSION"));

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
    reqwest::Client::builder()
        .dns_resolver(Arc::new(TracingResolver::new()))
        .use_preconfigured_tls(rustls_platform_verifier::tls_config())
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(30))
        .build()
        .expect("failed to create HTTP client")
}

async fn send_traced(
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, reqwest::Error> {
    // TODO: have in-flight and request metrics
    let (client, request) = request.build_split();
    let mut request = request?;

    let headers = request.headers();
    let host = headers.typed_get::<Host>().map(tracing::field::display);
    let user_agent = headers
        .typed_get::<UserAgent>()
        .map(tracing::field::display);
    let content_length = headers.typed_get().map(|ContentLength(len)| len);

    // Create a new span for the request
    let span = tracing::info_span!(
        "http.client.request",
        "otel.kind" = "client",
        "otel.status_code" = tracing::field::Empty,
        { HTTP_REQUEST_METHOD } = %request.method(),
        { URL_FULL } = %request.url(),
        { HTTP_RESPONSE_STATUS_CODE } = tracing::field::Empty,
        { SERVER_ADDRESS } = host,
        { HTTP_REQUEST_BODY_SIZE } = content_length,
        { HTTP_RESPONSE_BODY_SIZE } = tracing::field::Empty,
        { NETWORK_TRANSPORT } = "tcp",
        { NETWORK_TYPE } = tracing::field::Empty,
        { SERVER_ADDRESS } = tracing::field::Empty,
        { SERVER_PORT } = tracing::field::Empty,
        { CLIENT_ADDRESS } = tracing::field::Empty,
        { CLIENT_PORT } = tracing::field::Empty,
        { USER_AGENT_ORIGINAL } = user_agent,
        "rust.error" = tracing::field::Empty,
    );

    // Inject the span context into the request headers
    let context = span.context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        let mut injector = HeaderInjector(request.headers_mut());
        propagator.inject_context(&context, &mut injector);
    });

    async move {
        let span = tracing::Span::current();
        match client.execute(request).await {
            Ok(response) => {
                span.record("otel.status_code", "OK");
                span.record(HTTP_RESPONSE_STATUS_CODE, response.status().as_u16());

                if let Some(ContentLength(content_length)) = response.headers().typed_get() {
                    span.record(HTTP_RESPONSE_BODY_SIZE, content_length);
                }

                if let Some(http_info) = response.extensions().get::<HttpInfo>() {
                    let local = http_info.local_addr();
                    let remote = http_info.remote_addr();

                    let family = if local.is_ipv4() { "ipv4" } else { "ipv6" };
                    span.record(NETWORK_TYPE, family);
                    span.record(CLIENT_ADDRESS, remote.ip().to_string());
                    span.record(CLIENT_PORT, remote.port());
                    span.record(SERVER_ADDRESS, local.ip().to_string());
                    span.record(SERVER_PORT, local.port());
                } else {
                    tracing::warn!("No HttpInfo injected in response extensions");
                }

                Ok(response)
            }
            Err(err) => {
                span.record("otel.status_code", "ERROR");
                span.record("rust.error", &err as &dyn std::error::Error);
                Err(err)
            }
        }
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
