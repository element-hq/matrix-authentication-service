// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use tower::Service;

use super::future::TraceFuture;

#[derive(Clone, Debug)]
pub struct TraceService<S, MakeSpan, OnResponse = (), OnError = ()> {
    inner: S,
    make_span: MakeSpan,
    on_response: OnResponse,
    on_error: OnError,
}

impl<S, MakeSpan, OnResponse, OnError> TraceService<S, MakeSpan, OnResponse, OnError> {
    /// Create a new [`TraceService`].
    #[must_use]
    pub fn new(inner: S, make_span: MakeSpan, on_response: OnResponse, on_error: OnError) -> Self {
        Self {
            inner,
            make_span,
            on_response,
            on_error,
        }
    }
}

impl<R, S, MakeSpan, OnResponse, OnError> Service<R>
    for TraceService<S, MakeSpan, OnResponse, OnError>
where
    S: Service<R>,
    MakeSpan: super::make_span::MakeSpan<R>,
    OnResponse: super::enrich_span::EnrichSpan<S::Response> + Clone,
    OnError: super::enrich_span::EnrichSpan<S::Error> + Clone,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = TraceFuture<S::Future, OnResponse, OnError>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        let span = self.make_span.make_span(&request);
        let guard = span.enter();
        let inner = self.inner.call(request);
        drop(guard);

        TraceFuture::new(inner, span, self.on_response.clone(), self.on_error.clone())
    }
}
