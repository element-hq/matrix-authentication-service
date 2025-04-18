// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{
    pin::Pin,
    sync::atomic::Ordering,
    task::{Context, Poll},
};

use quanta::Instant;
use tokio::task::futures::TaskLocalFuture;

use crate::LogContext;

pub type LogContextFuture<F> = TaskLocalFuture<crate::LogContext, PollRecordingFuture<F>>;

impl LogContext {
    /// Wrap a future with the given log context
    pub(crate) fn wrap_future<F: Future>(&self, future: F) -> LogContextFuture<F> {
        let future = PollRecordingFuture::new(future);
        crate::CURRENT_LOG_CONTEXT.scope(self.clone(), future)
    }
}

pin_project_lite::pin_project! {
    /// A future which records the elapsed time and the number of polls in the
    /// active log context
    pub struct PollRecordingFuture<F> {
        #[pin]
        inner: F,
    }
}

impl<F: Future> PollRecordingFuture<F> {
    pub(crate) fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F: Future> Future for PollRecordingFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let start = Instant::now();
        let this = self.project();
        let result = this.inner.poll(cx);

        // Record the number of polls and the time we spent polling the future
        let elapsed = start.elapsed().as_nanos().try_into().unwrap_or(u64::MAX);
        let _ = crate::CURRENT_LOG_CONTEXT.try_with(|c| {
            c.inner.polls.fetch_add(1, Ordering::Relaxed);
            c.inner.cpu_time.fetch_add(elapsed, Ordering::Relaxed);
        });

        result
    }
}
