// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use headers::{ContentLength, HeaderMapExt, Host, UserAgent};
use http::{header::USER_AGENT, HeaderValue, Request, Response};
use hyper_util::client::legacy::connect::HttpInfo;
use mas_tower::{
    DurationRecorderLayer, DurationRecorderService, EnrichSpan, InFlightCounterLayer,
    InFlightCounterService, MakeSpan, MetricsAttributes, TraceContextLayer, TraceContextService,
    TraceLayer, TraceService,
};
use opentelemetry::KeyValue;
use opentelemetry_semantic_conventions::{
    attribute::{HTTP_REQUEST_BODY_SIZE, HTTP_RESPONSE_BODY_SIZE},
    trace::{
        CLIENT_ADDRESS, CLIENT_PORT, HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE,
        NETWORK_PROTOCOL_NAME, NETWORK_TRANSPORT, NETWORK_TYPE, SERVER_ADDRESS, SERVER_PORT,
        URL_FULL, USER_AGENT_ORIGINAL,
    },
};
use tower::{
    limit::{ConcurrencyLimit, GlobalConcurrencyLimitLayer},
    Layer,
};
use tower_http::{
    follow_redirect::{FollowRedirect, FollowRedirectLayer},
    set_header::{SetRequestHeader, SetRequestHeaderLayer},
};
use tracing::Span;

pub type ClientService<S> = SetRequestHeader<
    DurationRecorderService<
        InFlightCounterService<
            ConcurrencyLimit<
                FollowRedirect<
                    TraceService<
                        TraceContextService<S>,
                        MakeSpanForRequest,
                        EnrichSpanOnResponse,
                        EnrichSpanOnError,
                    >,
                >,
            >,
            OnRequestLabels,
        >,
        OnRequestLabels,
        OnResponseLabels,
        KeyValue,
    >,
    HeaderValue,
>;

#[derive(Debug, Clone, Default)]
pub struct MakeSpanForRequest {
    category: Option<&'static str>,
}

impl<B> MakeSpan<Request<B>> for MakeSpanForRequest {
    fn make_span(&self, request: &Request<B>) -> Span {
        let headers = request.headers();
        let host = headers.typed_get::<Host>().map(tracing::field::display);
        let user_agent = headers
            .typed_get::<UserAgent>()
            .map(tracing::field::display);
        let content_length = headers.typed_get().map(|ContentLength(len)| len);
        let category = self.category.unwrap_or("UNSET");

        tracing::info_span!(
            "http.client.request",
            "otel.kind" = "client",
            "otel.status_code" = tracing::field::Empty,
            { HTTP_REQUEST_METHOD } = %request.method(),
            { URL_FULL } = %request.uri(),
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
            "mas.category" = category,
        )
    }
}

#[derive(Debug, Clone)]
pub struct EnrichSpanOnResponse;

impl<B> EnrichSpan<Response<B>> for EnrichSpanOnResponse {
    fn enrich_span(&self, span: &Span, response: &Response<B>) {
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
    }
}

#[derive(Debug, Clone)]
pub struct EnrichSpanOnError;

impl<E> EnrichSpan<E> for EnrichSpanOnError
where
    E: std::error::Error + 'static,
{
    fn enrich_span(&self, span: &Span, error: &E) {
        span.record("otel.status_code", "ERROR");
        span.record("rust.error", error as &dyn std::error::Error);
    }
}

#[derive(Debug, Clone, Default)]
pub struct OnRequestLabels {
    category: Option<&'static str>,
}

impl<B> MetricsAttributes<Request<B>> for OnRequestLabels
where
    B: 'static,
{
    type Iter<'a> = std::array::IntoIter<KeyValue, 3>;
    fn attributes<'a>(&'a self, t: &'a Request<B>) -> Self::Iter<'a> {
        [
            KeyValue::new(HTTP_REQUEST_METHOD, t.method().as_str().to_owned()),
            KeyValue::new(NETWORK_PROTOCOL_NAME, "http"),
            KeyValue::new("mas.category", self.category.unwrap_or("UNSET")),
        ]
        .into_iter()
    }
}

#[derive(Debug, Clone, Default)]
pub struct OnResponseLabels;

impl<B> MetricsAttributes<Response<B>> for OnResponseLabels
where
    B: 'static,
{
    type Iter<'a> = std::iter::Once<KeyValue>;
    fn attributes<'a>(&'a self, t: &'a Response<B>) -> Self::Iter<'a> {
        std::iter::once(KeyValue::new(
            HTTP_RESPONSE_STATUS_CODE,
            i64::from(t.status().as_u16()),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ClientLayer {
    user_agent_layer: SetRequestHeaderLayer<HeaderValue>,
    concurrency_limit_layer: GlobalConcurrencyLimitLayer,
    follow_redirect_layer: FollowRedirectLayer,
    trace_layer: TraceLayer<MakeSpanForRequest, EnrichSpanOnResponse, EnrichSpanOnError>,
    trace_context_layer: TraceContextLayer,
    duration_recorder_layer: DurationRecorderLayer<OnRequestLabels, OnResponseLabels, KeyValue>,
    in_flight_counter_layer: InFlightCounterLayer<OnRequestLabels>,
}

impl Default for ClientLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientLayer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            user_agent_layer: SetRequestHeaderLayer::overriding(
                USER_AGENT,
                HeaderValue::from_static("matrix-authentication-service/0.0.1"),
            ),
            concurrency_limit_layer: GlobalConcurrencyLimitLayer::new(10),
            follow_redirect_layer: FollowRedirectLayer::new(),
            trace_layer: TraceLayer::new(MakeSpanForRequest::default())
                .on_response(EnrichSpanOnResponse)
                .on_error(EnrichSpanOnError),
            trace_context_layer: TraceContextLayer::new(),
            duration_recorder_layer: DurationRecorderLayer::new("http.client.duration")
                .on_request(OnRequestLabels::default())
                .on_response(OnResponseLabels)
                .on_error(KeyValue::new("http.error", true)),
            in_flight_counter_layer: InFlightCounterLayer::new("http.client.active_requests")
                .on_request(OnRequestLabels::default()),
        }
    }

    #[must_use]
    pub fn with_category(mut self, category: &'static str) -> Self {
        self.trace_layer = TraceLayer::new(MakeSpanForRequest {
            category: Some(category),
        })
        .on_response(EnrichSpanOnResponse)
        .on_error(EnrichSpanOnError);

        self.duration_recorder_layer = self.duration_recorder_layer.on_request(OnRequestLabels {
            category: Some(category),
        });

        self.in_flight_counter_layer = self.in_flight_counter_layer.on_request(OnRequestLabels {
            category: Some(category),
        });

        self
    }
}

impl<S> Layer<S> for ClientLayer
where
    S: Clone,
{
    type Service = ClientService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        (
            &self.user_agent_layer,
            &self.duration_recorder_layer,
            &self.in_flight_counter_layer,
            &self.concurrency_limit_layer,
            &self.follow_redirect_layer,
            &self.trace_layer,
            &self.trace_context_layer,
        )
            .layer(inner)
    }
}
