// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::Stream;
use tracing::Span;
use tracing_indicatif::span_ext::IndicatifSpanExt as _;

pin_project_lite::pin_project! {
    pub struct ProgressStream<S> {
        #[pin]
        stream: S,
        span: Span,
        counter: u64,
        batch_size: u64,
    }
}

impl<S> ProgressStream<S> {
    fn new(stream: S, span: Span, batch_size: u64) -> Self {
        Self {
            stream,
            span,
            counter: 0,
            batch_size,
        }
    }
}

impl<S> Stream for ProgressStream<S>
where
    S: Stream,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let item = this.stream.poll_next(cx);
        if let Poll::Ready(Some(_)) = item {
            *this.counter += 1;
            if *this.counter % *this.batch_size == 0 {
                this.span.pb_set_position(*this.counter);
            }
        }
        item
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}

/// Extension trait for [`Stream`] to add progress bar to the stream.
pub trait ProgressStreamExt: Stream {
    /// Add progress bar to the stream.
    fn with_progress_bar(self, length: u64, batch_size: u64) -> ProgressStream<Self>
    where
        Self: Sized,
    {
        let span = Span::current();
        span.pb_set_length(length);
        ProgressStream::new(self, span, batch_size)
    }
}

impl<S> ProgressStreamExt for S where S: Stream {}
