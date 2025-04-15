// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod future;
mod layer;
mod service;

use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use quanta::Instant;
use tokio::task_local;

pub use self::{
    future::{LogContextFuture, PollRecordingFuture},
    layer::LogContextLayer,
    service::LogContextService,
};

/// A counter which increments each time we create a new log context
/// It will wrap around if we create more than [`u64::MAX`] contexts
static LOG_CONTEXT_INDEX: AtomicU64 = AtomicU64::new(0);
task_local! {
    pub static CURRENT_LOG_CONTEXT: LogContext;
}

/// A log context saves informations about the current task, such as the
/// elapsed time, the number of polls, and the poll time.
#[derive(Clone)]
pub struct LogContext {
    inner: Arc<LogContextInner>,
}

struct LogContextInner {
    /// A user-defined tag for the log context
    tag: Cow<'static, str>,

    /// A unique index for the log context
    index: u64,

    /// The time when the context was created
    start: Instant,

    /// The number of [`Future::poll`] recorded
    polls: AtomicU64,

    /// An approximation of the total CPU time spent in the context
    cpu_time: AtomicU64,
}

impl LogContext {
    /// Create a new log context with the given tag
    pub fn new(tag: impl Into<Cow<'static, str>>) -> Self {
        let tag = tag.into();
        let inner = LogContextInner {
            tag,
            index: LOG_CONTEXT_INDEX.fetch_add(1, Ordering::Relaxed),
            start: Instant::now(),
            polls: AtomicU64::new(0),
            cpu_time: AtomicU64::new(0),
        };

        Self {
            inner: Arc::new(inner),
        }
    }

    /// Get a copy of the current log context, if any
    pub fn current() -> Option<Self> {
        CURRENT_LOG_CONTEXT.try_with(Self::clone).ok()
    }

    /// Run the async function `f` with the given log context. It will wrap the
    /// output future to record poll and CPU statistics.
    pub fn run<F: FnOnce() -> Fut, Fut: Future>(&self, f: F) -> LogContextFuture<Fut> {
        let future = self.run_sync(f);
        self.wrap_future(future)
    }

    /// Run the sync function `f` with the given log context, recording the CPU
    /// time spent.
    pub fn run_sync<F: FnOnce() -> R, R>(&self, f: F) -> R {
        let start = Instant::now();
        let result = CURRENT_LOG_CONTEXT.sync_scope(self.clone(), f);
        let elapsed = start.elapsed().as_nanos().try_into().unwrap_or(u64::MAX);
        self.inner.cpu_time.fetch_add(elapsed, Ordering::Relaxed);
        result
    }
}

impl std::fmt::Display for LogContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[expect(clippy::cast_precision_loss)]
        let elapsed = self.inner.start.elapsed().as_nanos() as f64 / 1_000_000.;

        #[expect(clippy::cast_precision_loss)]
        let cpu_time_ms = self.inner.cpu_time.load(Ordering::Relaxed) as f64 / 1_000_000.;

        let polls = self.inner.polls.load(Ordering::Relaxed);
        let tag = &self.inner.tag;
        let index = self.inner.index;
        write!(
            f,
            "{tag}-{index} ({polls} polls, CPU: {cpu_time_ms:.3} ms, total: {elapsed:.3} ms)"
        )
    }
}

/// A helper which implements `Display` for printing the current log context
#[derive(Debug, Clone, Copy)]
pub struct CurrentLogContext;

impl std::fmt::Display for CurrentLogContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        CURRENT_LOG_CONTEXT
            .try_with(|c| c.fmt(f))
            .unwrap_or_else(|_| "<no context>".fmt(f))
    }
}
