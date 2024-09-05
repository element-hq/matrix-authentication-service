// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{
    fmt,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use tower::{BoxError, Service, ServiceExt};

/// Type for the underlying HTTP service.
///
/// Allows implementors to use different libraries that provide a [`Service`]
/// that implements [`Clone`] + [`Send`] + [`Sync`].
pub type HttpService = BoxCloneSyncService<http::Request<Bytes>, http::Response<Bytes>, BoxError>;

impl fmt::Debug for HttpService {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("HttpService").finish()
    }
}

/// A [`Clone`] + [`Send`] + [`Sync`] boxed [`Service`].
///
/// [`BoxCloneSyncService`] turns a service into a trait object, allowing the
/// response future type to be dynamic, and allowing the service to be cloned.
#[allow(clippy::type_complexity)]
pub struct BoxCloneSyncService<T, U, E>(
    Box<
        dyn CloneSyncService<T, Response = U, Error = E, Future = BoxFuture<'static, Result<U, E>>>,
    >,
);

impl<T, U, E> BoxCloneSyncService<T, U, E> {
    /// Create a new `BoxCloneSyncService`.
    pub fn new<S>(inner: S) -> Self
    where
        S: Service<T, Response = U, Error = E> + Clone + Send + Sync + 'static,
        S::Future: Send + 'static,
    {
        let inner = inner.map_future(|f| Box::pin(f) as _);
        Self(Box::new(inner))
    }
}

impl<T, U, E> Service<T> for BoxCloneSyncService<T, U, E> {
    type Response = U;
    type Error = E;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    #[inline]
    fn call(&mut self, request: T) -> Self::Future {
        self.0.call(request)
    }
}

impl<T, U, E> Clone for BoxCloneSyncService<T, U, E> {
    fn clone(&self) -> Self {
        Self(self.0.clone_sync_box())
    }
}

trait CloneSyncService<R>: Service<R> + Send + Sync {
    fn clone_sync_box(
        &self,
    ) -> Box<
        dyn CloneSyncService<
            R,
            Response = Self::Response,
            Error = Self::Error,
            Future = Self::Future,
        >,
    >;
}

impl<R, T> CloneSyncService<R> for T
where
    T: Service<R> + Send + Sync + Clone + 'static,
{
    fn clone_sync_box(
        &self,
    ) -> Box<dyn CloneSyncService<R, Response = T::Response, Error = T::Error, Future = T::Future>>
    {
        Box::new(self.clone())
    }
}
