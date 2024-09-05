// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{ops::RangeBounds, sync::OnceLock};

use http::{header::HeaderName, Request, Response, StatusCode};
use tower::Service;
use tower_http::cors::CorsLayer;

use crate::layers::{
    body_to_bytes_response::BodyToBytesResponse, bytes_to_body_request::BytesToBodyRequest,
    catch_http_codes::CatchHttpCodes, form_urlencoded_request::FormUrlencodedRequest,
    json_request::JsonRequest, json_response::JsonResponse,
};

static PROPAGATOR_HEADERS: OnceLock<Vec<HeaderName>> = OnceLock::new();

/// Notify the CORS layer what opentelemetry propagators are being used. This
/// helps whitelisting headers in CORS requests.
///
/// # Panics
///
/// When called twice
pub fn set_propagator(propagator: &dyn opentelemetry::propagation::TextMapPropagator) {
    let headers = propagator
        .fields()
        .map(|h| HeaderName::try_from(h).unwrap())
        .collect();

    tracing::debug!(
        ?headers,
        "Headers allowed in CORS requests for trace propagators set"
    );
    PROPAGATOR_HEADERS
        .set(headers)
        .expect(concat!(module_path!(), "::set_propagator was called twice"));
}

pub trait CorsLayerExt {
    #[must_use]
    fn allow_otel_headers<H>(self, headers: H) -> Self
    where
        H: IntoIterator<Item = HeaderName>;
}

impl CorsLayerExt for CorsLayer {
    fn allow_otel_headers<H>(self, headers: H) -> Self
    where
        H: IntoIterator<Item = HeaderName>,
    {
        let base = PROPAGATOR_HEADERS.get().cloned().unwrap_or_default();
        let headers: Vec<_> = headers.into_iter().chain(base).collect();
        self.allow_headers(headers)
    }
}

pub trait ServiceExt<Body>: Sized {
    fn request_bytes_to_body(self) -> BytesToBodyRequest<Self> {
        BytesToBodyRequest::new(self)
    }

    /// Adds a layer which collects all the response body into a contiguous
    /// byte buffer.
    /// This makes the response type `Response<Bytes>`.
    fn response_body_to_bytes(self) -> BodyToBytesResponse<Self> {
        BodyToBytesResponse::new(self)
    }

    fn json_response<T>(self) -> JsonResponse<Self, T> {
        JsonResponse::new(self)
    }

    fn json_request<T>(self) -> JsonRequest<Self, T> {
        JsonRequest::new(self)
    }

    fn form_urlencoded_request<T>(self) -> FormUrlencodedRequest<Self, T> {
        FormUrlencodedRequest::new(self)
    }

    /// Catches responses with the given status code and then maps those
    /// responses to an error type using the provided `mapper` function.
    fn catch_http_code<M, ResBody, E>(
        self,
        status_code: StatusCode,
        mapper: M,
    ) -> CatchHttpCodes<Self, M>
    where
        M: Fn(Response<ResBody>) -> E + Send + Clone + 'static,
    {
        self.catch_http_codes(status_code..=status_code, mapper)
    }

    /// Catches responses with the given status codes and then maps those
    /// responses to an error type using the provided `mapper` function.
    fn catch_http_codes<B, M, ResBody, E>(self, bounds: B, mapper: M) -> CatchHttpCodes<Self, M>
    where
        B: RangeBounds<StatusCode>,
        M: Fn(Response<ResBody>) -> E + Send + Clone + 'static,
    {
        CatchHttpCodes::new(self, bounds, mapper)
    }

    /// Shorthand for [`Self::catch_http_codes`] which catches all client errors
    /// (4xx) and server errors (5xx).
    fn catch_http_errors<M, ResBody, E>(self, mapper: M) -> CatchHttpCodes<Self, M>
    where
        M: Fn(Response<ResBody>) -> E + Send + Clone + 'static,
    {
        self.catch_http_codes(
            StatusCode::from_u16(400).unwrap()..StatusCode::from_u16(600).unwrap(),
            mapper,
        )
    }
}

impl<S, B> ServiceExt<B> for S where S: Service<Request<B>> {}
