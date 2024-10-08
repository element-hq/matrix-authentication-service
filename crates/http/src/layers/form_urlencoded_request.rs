// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{future::Ready, marker::PhantomData, task::Poll};

use bytes::Bytes;
use futures_util::{
    future::{Either, MapErr},
    FutureExt, TryFutureExt,
};
use headers::{ContentType, HeaderMapExt};
use http::Request;
use serde::Serialize;
use thiserror::Error;
use tower::{Layer, Service};

#[derive(Debug, Error)]
pub enum Error<Service> {
    #[error(transparent)]
    Service { inner: Service },

    #[error("could not serialize form payload")]
    Serialize {
        #[source]
        inner: serde_urlencoded::ser::Error,
    },
}

impl<S> Error<S> {
    fn service(source: S) -> Self {
        Self::Service { inner: source }
    }

    fn serialize(source: serde_urlencoded::ser::Error) -> Self {
        Self::Serialize { inner: source }
    }
}

#[derive(Clone)]
pub struct FormUrlencodedRequest<S, T> {
    inner: S,
    _t: PhantomData<T>,
}

impl<S, T> FormUrlencodedRequest<S, T> {
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            _t: PhantomData,
        }
    }
}

impl<S, T> Service<Request<T>> for FormUrlencodedRequest<S, T>
where
    S: Service<Request<Bytes>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    T: Serialize,
{
    type Error = Error<S::Error>;
    type Response = S::Response;
    type Future = Either<
        Ready<Result<Self::Response, Self::Error>>,
        MapErr<S::Future, fn(S::Error) -> Self::Error>,
    >;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::service)
    }

    fn call(&mut self, request: Request<T>) -> Self::Future {
        let (mut parts, body) = request.into_parts();

        parts.headers.typed_insert(ContentType::form_url_encoded());

        let body = match serde_urlencoded::to_string(&body) {
            Ok(body) => Bytes::from(body),
            Err(err) => return std::future::ready(Err(Error::serialize(err))).left_future(),
        };

        let request = Request::from_parts(parts, body);

        self.inner
            .call(request)
            .map_err(Error::service as fn(S::Error) -> Self::Error)
            .right_future()
    }
}

#[derive(Clone, Copy)]
pub struct FormUrlencodedRequestLayer<T> {
    _t: PhantomData<T>,
}

impl<T> Default for FormUrlencodedRequestLayer<T> {
    fn default() -> Self {
        Self { _t: PhantomData }
    }
}

impl<S, T> Layer<S> for FormUrlencodedRequestLayer<T> {
    type Service = FormUrlencodedRequest<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        FormUrlencodedRequest::new(inner)
    }
}
