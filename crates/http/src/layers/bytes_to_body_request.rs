// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use tower::{Layer, Service};

#[derive(Clone)]
pub struct BytesToBodyRequest<S> {
    inner: S,
}

impl<S> BytesToBodyRequest<S> {
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> Service<Request<Bytes>> for BytesToBodyRequest<S>
where
    S: Service<Request<Full<Bytes>>>,
    S::Future: Send + 'static,
{
    type Error = S::Error;
    type Response = S::Response;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Bytes>) -> Self::Future {
        let (parts, body) = request.into_parts();
        let body = Full::new(body);

        let request = Request::from_parts(parts, body);

        self.inner.call(request)
    }
}

#[derive(Default, Clone, Copy)]
pub struct BytesToBodyRequestLayer;

impl<S> Layer<S> for BytesToBodyRequestLayer {
    type Service = BytesToBodyRequest<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BytesToBodyRequest::new(inner)
    }
}
