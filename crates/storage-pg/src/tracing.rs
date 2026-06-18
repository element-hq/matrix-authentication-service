// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
    time::Instant,
};

use futures_util::{
    FutureExt, StreamExt,
    future::BoxFuture,
    stream::{BoxStream, Stream},
};
use mas_context::LogContext;
use opentelemetry_semantic_conventions::{
    attribute::DB_QUERY_TEXT, trace::DB_RESPONSE_RETURNED_ROWS,
};
use sqlx::{Database, Describe, Either, Error, Execute, Executor};
use tracing::Span;

/// An extension trait for [`sqlx::Execute`] that records the SQL statement as
/// `db.query.text` in a tracing span
pub trait ExecuteExt<'q, DB>: Sized {
    /// Records the statement as `db.query.text` in the current span
    #[must_use]
    fn traced(self) -> Self {
        self.record(&Span::current())
    }

    /// Records the statement as `db.query.text` in the given span
    #[must_use]
    fn record(self, span: &Span) -> Self;
}

impl<'q, DB, T> ExecuteExt<'q, DB> for T
where
    T: sqlx::Execute<'q, DB>,
    DB: sqlx::Database,
{
    fn record(self, span: &Span) -> Self {
        span.record(DB_QUERY_TEXT, self.sql());
        self
    }
}

pin_project_lite::pin_project! {
    /// A stream that records every row fetched from the database
    /// and tracks the elapsed wall-clock time.
    struct RecordingStream<St, Db> {
        #[pin]
        inner: St,
        span: Span,
        database: std::marker::PhantomData<Db>,
        start: Instant,
        fetched: usize,
    }
}

impl<Db: Database, St: Stream<Item = Result<Either<Db::QueryResult, Db::Row>, Error>>> Stream
    for RecordingStream<St, Db>
{
    type Item = St::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<St::Item>> {
        let this = self.project();
        let ret = match ready!(this.inner.poll_next(cx)) {
            Some(Ok(Either::Left(query_result))) => Some(Ok(Either::Left(query_result))),
            Some(Ok(Either::Right(row))) => {
                *this.fetched += 1;
                Some(Ok(Either::Right(row)))
            }
            Some(Err(err)) => Some(Err(err)),
            // Stream is terminated; log query stats and return `None`.
            None => {
                let elapsed = this.start.elapsed();
                this.span.record(DB_RESPONSE_RETURNED_ROWS, *this.fetched);
                LogContext::maybe_record_query_stats(*this.fetched, elapsed);
                None
            }
        };
        Poll::Ready(ret)
    }
}

/// An [`Executor`] wrapper that records the SQL of each query onto a span and
/// accumulates count/timing onto the [`LogContext`]. Only `fetch_many` and
/// `fetch_optional` are required; every other `Executor` method funnels through
/// them. Note that no stats are recorded in case of an error.
#[derive(Debug)]
struct RecordingExecutor<E> {
    inner: E,
    span: Span,
}

impl<E> RecordingExecutor<E> {
    fn new(inner: E, span: Span) -> Self {
        Self { inner, span }
    }
}

impl<'c, E> Executor<'c> for RecordingExecutor<E>
where
    E: Executor<'c>,
{
    type Database = E::Database;

    fn fetch_many<'e, 'q: 'e, Q>(
        self,
        query: Q,
    ) -> BoxStream<
        'e,
        Result<
            Either<<Self::Database as Database>::QueryResult, <Self::Database as Database>::Row>,
            Error,
        >,
    >
    where
        'c: 'e,
        Q: 'q + Execute<'q, E::Database>,
    {
        self.span.record(DB_QUERY_TEXT, query.sql());

        RecordingStream {
            inner: self.inner.fetch_many(query),
            database: std::marker::PhantomData::<E::Database>,
            span: self.span,
            start: Instant::now(),
            fetched: 0,
        }
        .boxed()
    }

    fn fetch_optional<'e, 'q: 'e, Q>(
        self,
        query: Q,
    ) -> BoxFuture<'e, Result<Option<<Self::Database as Database>::Row>, Error>>
    where
        'c: 'e,
        Q: 'q + Execute<'q, E::Database>,
    {
        self.span.record(DB_QUERY_TEXT, query.sql());
        let inner = self.inner.fetch_optional(query);
        async move {
            let start = Instant::now();
            let result = inner.await?;
            #[expect(clippy::bool_to_int_with_if, reason = "clearer if explicit")]
            let fetched = if result.is_some() { 1 } else { 0 };
            self.span.record(DB_RESPONSE_RETURNED_ROWS, fetched);
            LogContext::maybe_record_query_stats(fetched, start.elapsed());

            Ok(result)
        }
        .boxed()
    }

    fn prepare_with<'e, 'q: 'e>(
        self,
        sql: &'q str,
        parameters: &'e [<Self::Database as Database>::TypeInfo],
    ) -> BoxFuture<'e, Result<<Self::Database as Database>::Statement<'q>, Error>>
    where
        'c: 'e,
    {
        self.inner.prepare_with(sql, parameters)
    }

    fn describe<'e, 'q: 'e>(
        self,
        sql: &'q str,
    ) -> BoxFuture<'e, Result<Describe<Self::Database>, Error>>
    where
        'c: 'e,
    {
        self.inner.describe(sql)
    }
}
