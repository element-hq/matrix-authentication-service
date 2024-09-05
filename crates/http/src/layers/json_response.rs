// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{marker::PhantomData, task::Poll};

use bytes::Buf;
use futures_util::FutureExt;
use http::{header::ACCEPT, HeaderValue, Request, Response};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tower::{Layer, Service};

#[derive(Debug, Error)]
pub enum Error<Service> {
    /// An error from the inner service.
    #[error(transparent)]
    Service { inner: Service },

    #[error("could not parse JSON payload")]
    Deserialize {
        #[source]
        inner: serde_json::Error,
    },
}

impl<S> Error<S> {
    fn service(source: S) -> Self {
        Self::Service { inner: source }
    }

    fn deserialize(source: serde_json::Error) -> Self {
        Self::Deserialize { inner: source }
    }
}

#[derive(Clone)]
pub struct JsonResponse<S, T> {
    inner: S,
    _t: PhantomData<T>,
}

impl<S, T> JsonResponse<S, T> {
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            _t: PhantomData,
        }
    }
}

impl<S, T, B, C> Service<Request<B>> for JsonResponse<S, T>
where
    S: Service<Request<B>, Response = Response<C>>,
    S::Future: Send + 'static,
    C: Buf,
    T: DeserializeOwned,
{
    type Error = Error<S::Error>;
    type Response = Response<T>;
    type Future = futures_util::future::Map<
        S::Future,
        fn(Result<Response<C>, S::Error>) -> Result<Self::Response, Self::Error>,
    >;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::service)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        fn mapper<C, T, E>(res: Result<Response<C>, E>) -> Result<Response<T>, Error<E>>
        where
            C: Buf,
            T: DeserializeOwned,
        {
            let response = res.map_err(Error::service)?;
            let (parts, body) = response.into_parts();

            let body = serde_json::from_reader(body.reader()).map_err(Error::deserialize)?;

            let res = Response::from_parts(parts, body);
            Ok(res)
        }

        request
            .headers_mut()
            .insert(ACCEPT, HeaderValue::from_static("application/json"));

        self.inner.call(request).map(mapper::<C, T, S::Error>)
    }
}

#[derive(Clone, Copy)]
pub struct JsonResponseLayer<T> {
    _t: PhantomData<T>,
}

impl<T> Default for JsonResponseLayer<T> {
    fn default() -> Self {
        Self { _t: PhantomData }
    }
}

impl<S, T> Layer<S> for JsonResponseLayer<T> {
    type Service = JsonResponse<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        JsonResponse::new(inner)
    }
}
