// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Request, Response};
use http_body::Body;
use http_body_util::BodyExt;
use thiserror::Error;
use tower::{Layer, Service};

#[derive(Debug, Error)]
pub enum Error<ServiceError, BodyError> {
    #[error(transparent)]
    Service { inner: ServiceError },

    #[error(transparent)]
    Body { inner: BodyError },
}

impl<S, B> Error<S, B> {
    fn service(inner: S) -> Self {
        Self::Service { inner }
    }

    fn body(inner: B) -> Self {
        Self::Body { inner }
    }
}

impl<E> Error<E, E> {
    pub fn unify(self) -> E {
        match self {
            Self::Service { inner } | Self::Body { inner } => inner,
        }
    }
}

#[derive(Clone)]
pub struct BodyToBytesResponse<S> {
    inner: S,
}

impl<S> BodyToBytesResponse<S> {
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for BodyToBytesResponse<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    ResBody: Body + Send,
    ResBody::Data: Send,
{
    type Error = Error<S::Error, ResBody::Error>;
    type Response = Response<Bytes>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::service)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let inner = self.inner.call(request);

        let fut = async {
            let response = inner.await.map_err(Error::service)?;
            let (parts, body) = response.into_parts();

            let body = body.collect().await.map_err(Error::body)?.to_bytes();

            let response = Response::from_parts(parts, body);
            Ok(response)
        };

        Box::pin(fut)
    }
}

#[derive(Default, Clone, Copy)]
pub struct BodyToBytesResponseLayer;

impl<S> Layer<S> for BodyToBytesResponseLayer {
    type Service = BodyToBytesResponse<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyToBytesResponse::new(inner)
    }
}
