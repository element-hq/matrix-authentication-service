// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use opentelemetry::{KeyValue, Value};
use tower::{Layer, Service};

/// A simple static key-value pair.
#[derive(Clone, Debug)]
pub struct KV<V>(pub &'static str, pub V);

impl<V> From<KV<V>> for KeyValue
where
    V: Into<Value>,
{
    fn from(value: KV<V>) -> Self {
        Self::new(value.0, value.1.into())
    }
}

/// A wrapper around a function that can be used to generate a key-value pair,
/// make or enrich spans.
#[derive(Clone, Debug)]
pub struct FnWrapper<F>(pub F);

/// A no-op layer that has the request type bound.
#[derive(Clone, Copy, Debug)]
pub struct IdentityLayer<R> {
    _request: std::marker::PhantomData<R>,
}

impl<R> Default for IdentityLayer<R> {
    fn default() -> Self {
        Self {
            _request: std::marker::PhantomData,
        }
    }
}

/// A no-op service that has the request type bound.
#[derive(Clone, Copy, Debug)]
pub struct IdentityService<R, S> {
    _request: std::marker::PhantomData<R>,
    inner: S,
}

impl<R, S> Default for IdentityService<R, S>
where
    S: Default,
{
    fn default() -> Self {
        Self {
            _request: std::marker::PhantomData,
            inner: S::default(),
        }
    }
}

impl<R, S> Layer<S> for IdentityLayer<R> {
    type Service = IdentityService<R, S>;

    fn layer(&self, inner: S) -> Self::Service {
        IdentityService {
            _request: std::marker::PhantomData,
            inner,
        }
    }
}

impl<S, R> Service<R> for IdentityService<R, S>
where
    S: Service<R>,
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

    fn call(&mut self, req: R) -> Self::Future {
        self.inner.call(req)
    }
}
