// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use http::Request;
use opentelemetry::propagation::Injector;
use opentelemetry_http::HeaderInjector;
use tower::{Layer, Service};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// A trait to get an [`Injector`] from a request.
trait AsInjector {
    type Injector<'a>: Injector
    where
        Self: 'a;

    fn as_injector(&mut self) -> Self::Injector<'_>;
}

impl<B> AsInjector for Request<B> {
    type Injector<'a>
        = HeaderInjector<'a>
    where
        Self: 'a;

    fn as_injector(&mut self) -> Self::Injector<'_> {
        HeaderInjector(self.headers_mut())
    }
}

/// A [`Layer`] that adds a trace context to the request.
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceContextLayer {
    _private: (),
}

impl TraceContextLayer {
    /// Create a new [`TraceContextLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for TraceContextLayer {
    type Service = TraceContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceContextService::new(inner)
    }
}

/// A [`Service`] that adds a trace context to the request.
#[derive(Debug, Clone)]
pub struct TraceContextService<S> {
    inner: S,
}

impl<S> TraceContextService<S> {
    /// Create a new [`TraceContextService`].
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, R> Service<R> for TraceContextService<S>
where
    S: Service<R>,
    R: AsInjector,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: R) -> Self::Future {
        // Get the `opentelemetry` context out of the `tracing` span.
        let context = Span::current().context();

        // Inject the trace context into the request. The block is there to ensure that
        // the injector is dropped before calling the inner service, to avoid borrowing
        // issues.
        {
            let mut injector = req.as_injector();
            opentelemetry::global::get_text_map_propagator(|propagator| {
                propagator.inject_context(&context, &mut injector);
            });
        }

        self.inner.call(req)
    }
}
