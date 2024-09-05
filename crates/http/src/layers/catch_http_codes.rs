// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::ops::{Bound, RangeBounds};

use futures_util::FutureExt;
use http::{Request, Response, StatusCode};
use thiserror::Error;
use tower::{Layer, Service};

#[derive(Debug, Error)]
pub enum Error<S, E> {
    #[error(transparent)]
    Service { inner: S },

    #[error("request failed with status {status_code}: {inner}")]
    HttpError { status_code: StatusCode, inner: E },
}

impl<S, E> Error<S, E> {
    fn service(inner: S) -> Self {
        Self::Service { inner }
    }

    pub fn status_code(&self) -> Option<StatusCode> {
        match self {
            Self::Service { .. } => None,
            Self::HttpError { status_code, .. } => Some(*status_code),
        }
    }
}

/// A layer that catches responses with the HTTP status codes lying within
/// `bounds` and then maps the requests into a custom error type using `mapper`.
#[derive(Clone)]
pub struct CatchHttpCodes<S, M> {
    /// The inner service
    inner: S,
    /// Which HTTP status codes to catch
    bounds: (Bound<StatusCode>, Bound<StatusCode>),
    /// The function used to convert errors, which must be
    /// `Fn(Response<ResBody>) -> E + Send + Clone + 'static`.
    mapper: M,
}

impl<S, M> CatchHttpCodes<S, M> {
    pub fn new<B>(inner: S, bounds: B, mapper: M) -> Self
    where
        B: RangeBounds<StatusCode>,
        M: Clone,
    {
        let bounds = (bounds.start_bound().cloned(), bounds.end_bound().cloned());
        Self {
            inner,
            bounds,
            mapper,
        }
    }
}

impl<S, M, E, ReqBody, ResBody> Service<Request<ReqBody>> for CatchHttpCodes<S, M>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    M: Fn(Response<ResBody>) -> E + Send + Clone + 'static,
{
    type Error = Error<S::Error, E>;
    type Response = Response<ResBody>;
    type Future = futures_util::future::Map<
        S::Future,
        Box<
            dyn Fn(Result<S::Response, S::Error>) -> Result<Self::Response, Self::Error>
                + Send
                + 'static,
        >,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::service)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let fut = self.inner.call(request);
        let bounds = self.bounds;
        let mapper = self.mapper.clone();

        fut.map(Box::new(move |res: Result<S::Response, S::Error>| {
            let response = res.map_err(Error::service)?;
            let status_code = response.status();

            if bounds.contains(&status_code) {
                let inner = mapper(response);
                Err(Error::HttpError { status_code, inner })
            } else {
                Ok(response)
            }
        }))
    }
}

#[derive(Clone)]
pub struct CatchHttpCodesLayer<M> {
    bounds: (Bound<StatusCode>, Bound<StatusCode>),
    mapper: M,
}

impl<M> CatchHttpCodesLayer<M>
where
    M: Clone,
{
    pub fn new<B>(bounds: B, mapper: M) -> Self
    where
        B: RangeBounds<StatusCode>,
    {
        let bounds = (bounds.start_bound().cloned(), bounds.end_bound().cloned());
        Self { bounds, mapper }
    }

    pub fn exact(status_code: StatusCode, mapper: M) -> Self {
        Self::new(status_code..=status_code, mapper)
    }
}

impl<S, M> Layer<S> for CatchHttpCodesLayer<M>
where
    M: Clone,
{
    type Service = CatchHttpCodes<S, M>;

    fn layer(&self, inner: S) -> Self::Service {
        CatchHttpCodes::new(inner, self.bounds, self.mapper.clone())
    }
}
