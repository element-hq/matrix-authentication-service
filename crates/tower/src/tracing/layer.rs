// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use tower::Layer;
use tracing::Span;

use crate::{enrich_span_fn, make_span_fn, utils::FnWrapper};

#[derive(Clone, Debug)]
pub struct TraceLayer<MakeSpan, OnResponse = (), OnError = ()> {
    make_span: MakeSpan,
    on_response: OnResponse,
    on_error: OnError,
}

impl<F> TraceLayer<FnWrapper<F>> {
    #[must_use]
    pub fn from_fn<T>(f: F) -> TraceLayer<FnWrapper<F>>
    where
        F: Fn(&T) -> Span,
    {
        TraceLayer::new(make_span_fn(f))
    }
}

impl<MakeSpan> TraceLayer<MakeSpan> {
    #[must_use]
    pub fn new(make_span: MakeSpan) -> Self {
        Self {
            make_span,
            on_response: (),
            on_error: (),
        }
    }
}

impl<MakeSpan, OnResponse, OnError> TraceLayer<MakeSpan, OnResponse, OnError> {
    #[must_use]
    pub fn on_response<NewOnResponse>(
        self,
        on_response: NewOnResponse,
    ) -> TraceLayer<MakeSpan, NewOnResponse, OnError> {
        TraceLayer {
            make_span: self.make_span,
            on_response,
            on_error: self.on_error,
        }
    }

    #[must_use]
    pub fn on_response_fn<F, T>(self, f: F) -> TraceLayer<MakeSpan, FnWrapper<F>, OnError>
    where
        F: Fn(&Span, &T),
    {
        self.on_response(enrich_span_fn(f))
    }

    #[must_use]
    pub fn on_error<NewOnError>(
        self,
        on_error: NewOnError,
    ) -> TraceLayer<MakeSpan, OnResponse, NewOnError> {
        TraceLayer {
            make_span: self.make_span,
            on_response: self.on_response,
            on_error,
        }
    }

    pub fn on_error_fn<F, E>(self, f: F) -> TraceLayer<MakeSpan, OnResponse, FnWrapper<F>>
    where
        F: Fn(&Span, &E),
    {
        self.on_error(enrich_span_fn(f))
    }
}

impl<S, MakeSpan, OnResponse, OnError> Layer<S> for TraceLayer<MakeSpan, OnResponse, OnError>
where
    MakeSpan: Clone,
    OnResponse: Clone,
    OnError: Clone,
{
    type Service = super::service::TraceService<S, MakeSpan, OnResponse, OnError>;

    fn layer(&self, inner: S) -> Self::Service {
        super::service::TraceService::new(
            inner,
            self.make_span.clone(),
            self.on_response.clone(),
            self.on_error.clone(),
        )
    }
}
