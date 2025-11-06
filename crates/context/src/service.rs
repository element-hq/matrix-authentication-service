// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    borrow::Cow,
    task::{Context, Poll},
};

use tower_service::Service;

use crate::{LogContext, LogContextFuture};

/// A service which wraps another service and creates a log context for
/// each request.
pub struct LogContextService<S, R> {
    inner: S,
    tagger: fn(&R) -> Cow<'static, str>,
}

impl<S: Clone, R> Clone for LogContextService<S, R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            tagger: self.tagger,
        }
    }
}

impl<S, R> LogContextService<S, R> {
    pub fn new(inner: S, tagger: fn(&R) -> Cow<'static, str>) -> Self {
        Self { inner, tagger }
    }
}

impl<S, R> Service<R> for LogContextService<S, R>
where
    S: Service<R>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = LogContextFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: R) -> Self::Future {
        let tag = (self.tagger)(&req);
        let log_context = LogContext::new(tag);
        log_context.run(|| self.inner.call(req))
    }
}
