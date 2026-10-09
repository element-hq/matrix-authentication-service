// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Records each executed SQL statement as `db.query.text` on the current
//! tracing span, and accumulates per-context DB query count and timing onto the
//! [`LogContext`].
//!
//! Recording happens at the *executor* layer rather than at `.traced()` time:
//! [`ExecuteExt::traced`] wraps the query in a [`Traced`], whose `fetch_*` /
//! `execute` methods substitute a [`RecordingExecutor`] for the real executor.
//! The recording executor reads the SQL, records it, and times the query as it
//! runs.

use std::{
    future::ready,
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
use sqlx::{
    Database, Describe, Either, Error, Execute, Executor, IntoArguments, SqlStr, Statement,
    error::BoxDynError,
    query::{Map, Query, QueryAs, QueryScalar},
};
use tracing::Span;

/// An extension trait that wraps a sqlx query so its SQL and timing get
/// recorded when it is executed.
///
/// The span attached should have the `db.query.text` and
/// `db.response.returned_rows` attribute set.
pub trait ExecuteExt: Sized {
    /// Wrap the query so that, when executed, its SQL is recorded as
    /// `db.query.text` on the current span and its count/timing are added to
    /// the current [`LogContext`].
    #[must_use]
    fn traced(self) -> Traced<Self> {
        self.record(&Span::current())
    }

    /// Like [`ExecuteExt::traced`], but records onto the given span instead of
    /// the current one. Use when the query runs under a span other than the
    /// one current at the call site.
    #[must_use]
    fn record(self, span: &Span) -> Traced<Self> {
        Traced {
            query: self,
            span: span.clone(),
        }
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

/// A query rebuilt from the parts of another one, as reading the SQL of a
/// query that is not a prepared statement consumes it.
struct TakenQuery<DB: Database> {
    sql: SqlStr,
    arguments: Option<DB::Arguments>,
    persistent: bool,
}

impl<DB: Database> TakenQuery<DB> {
    /// Take the query apart, recording its SQL on the span even if encoding
    /// its arguments fails.
    fn new<'q, Q: Execute<'q, DB>>(mut query: Q, span: &Span) -> Result<Self, Error> {
        let persistent = query.persistent();
        let arguments = query.take_arguments();
        let sql = query.sql();
        span.record(DB_QUERY_TEXT, sql.as_str());

        Ok(Self {
            sql,
            arguments: arguments.map_err(Error::Encode)?,
            persistent,
        })
    }
}

impl<DB: Database> Execute<'_, DB> for TakenQuery<DB> {
    fn sql(self) -> SqlStr {
        self.sql
    }

    fn statement(&self) -> Option<&DB::Statement> {
        None
    }

    fn take_arguments(&mut self) -> Result<Option<DB::Arguments>, BoxDynError> {
        Ok(self.arguments.take())
    }

    fn persistent(&self) -> bool {
        self.persistent
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
        let inner = if let Some(statement) = query.statement() {
            // If the query is a cached prepared statement, we can inspect its
            // SQL without consuming the query
            self.span.record(DB_QUERY_TEXT, statement.sql().as_str());
            self.inner.fetch_many(query)
        } else {
            match TakenQuery::new(query, &self.span) {
                Ok(query) => self.inner.fetch_many(query),
                Err(err) => return futures_util::stream::once(ready(Err(err))).boxed(),
            }
        };

        RecordingStream {
            inner,
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
        let inner = if let Some(statement) = query.statement() {
            // If the query is a cached prepared statement, we can inspect its
            // SQL without consuming the query
            self.span.record(DB_QUERY_TEXT, statement.sql().as_str());
            self.inner.fetch_optional(query)
        } else {
            match TakenQuery::new(query, &self.span) {
                Ok(query) => self.inner.fetch_optional(query),
                Err(err) => return ready(Err(err)).boxed(),
            }
        };

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

    fn prepare_with<'e>(
        self,
        sql: SqlStr,
        parameters: &'e [<Self::Database as Database>::TypeInfo],
    ) -> BoxFuture<'e, Result<<Self::Database as Database>::Statement, Error>>
    where
        'c: 'e,
    {
        self.inner.prepare_with(sql, parameters)
    }

    fn describe<'e>(self, sql: SqlStr) -> BoxFuture<'e, Result<Describe<Self::Database>, Error>>
    where
        'c: 'e,
    {
        self.inner.describe(sql)
    }
}

/// A query wrapped by [`ExecuteExt::traced`], carrying the span to record onto.
pub struct Traced<Q> {
    query: Q,
    span: Span,
}

// Implementation of the [`ExecuteExt`] trait for each concrete query type we
// care about. We avoid a blanket impl to avoid the methods being available on
// all types.
impl<DB: Database, A> ExecuteExt for Query<'_, DB, A> {}
impl<DB: Database, O, A> ExecuteExt for QueryAs<'_, DB, O, A> {}
impl<DB: Database, O, A> ExecuteExt for QueryScalar<'_, DB, O, A> {}
impl<DB: Database, F, A> ExecuteExt for Map<'_, DB, F, A> {}

// Each concrete query type needs its own delegating impl: `Map`/`QueryAs`/
// `QueryScalar` apply their row-mapping in their *own* inherent `fetch_*`
// methods (returning the mapped output), so we must call those, wrapping the
// executor with a [`RecordingExecutor`] to record the span.

impl<'q, DB: Database, A> Traced<Query<'q, DB, A>>
where
    A: 'q + Send + IntoArguments<DB>,
{
    pub async fn execute<'e, 'c, E>(self, executor: E) -> Result<DB::QueryResult, Error>
    where
        'c: 'e,
        'q: 'e,
        A: 'e,
        E: Executor<'c, Database = DB>,
    {
        self.query
            .execute(RecordingExecutor::new(executor, self.span))
            .await
    }

    pub async fn fetch_one<'e, 'c, E>(self, executor: E) -> Result<DB::Row, Error>
    where
        'c: 'e,
        'q: 'e,
        A: 'e,
        E: Executor<'c, Database = DB>,
    {
        self.query
            .fetch_one(RecordingExecutor::new(executor, self.span))
            .await
    }

    pub async fn fetch_optional<'e, 'c, E>(self, executor: E) -> Result<Option<DB::Row>, Error>
    where
        'c: 'e,
        'q: 'e,
        A: 'e,
        E: Executor<'c, Database = DB>,
    {
        self.query
            .fetch_optional(RecordingExecutor::new(executor, self.span))
            .await
    }

    pub async fn fetch_all<'e, 'c, E>(self, executor: E) -> Result<Vec<DB::Row>, Error>
    where
        'c: 'e,
        'q: 'e,
        A: 'e,
        E: Executor<'c, Database = DB>,
    {
        self.query
            .fetch_all(RecordingExecutor::new(executor, self.span))
            .await
    }
}

impl<'q, DB: Database, F, O, A> Traced<Map<'q, DB, F, A>>
where
    F: FnMut(DB::Row) -> Result<O, Error> + Send,
    O: Send + Unpin,
    A: 'q + Send + IntoArguments<DB>,
{
    pub async fn fetch_one<'e, 'c, E>(self, executor: E) -> Result<O, Error>
    where
        'c: 'e,
        'q: 'e,
        E: 'e + Executor<'c, Database = DB>,
        F: 'e,
        O: 'e,
    {
        self.query
            .fetch_one(RecordingExecutor::new(executor, self.span))
            .await
    }

    pub async fn fetch_optional<'e, 'c, E>(self, executor: E) -> Result<Option<O>, Error>
    where
        'c: 'e,
        'q: 'e,
        E: 'e + Executor<'c, Database = DB>,
        F: 'e,
        O: 'e,
    {
        self.query
            .fetch_optional(RecordingExecutor::new(executor, self.span))
            .await
    }

    pub async fn fetch_all<'e, 'c, E>(self, executor: E) -> Result<Vec<O>, Error>
    where
        'c: 'e,
        'q: 'e,
        E: 'e + Executor<'c, Database = DB>,
        F: 'e,
        O: 'e,
    {
        self.query
            .fetch_all(RecordingExecutor::new(executor, self.span))
            .await
    }
}

impl<'q, DB: Database, O, A> Traced<QueryAs<'q, DB, O, A>>
where
    A: 'q + IntoArguments<DB>,
    O: Send + Unpin + for<'r> sqlx::FromRow<'r, DB::Row>,
{
    pub async fn fetch_one<'e, 'c, E>(self, executor: E) -> Result<O, Error>
    where
        'c: 'e,
        'q: 'e,
        O: 'e,
        A: 'e,
        E: 'e + Executor<'c, Database = DB>,
    {
        self.query
            .fetch_one(RecordingExecutor::new(executor, self.span))
            .await
    }

    pub async fn fetch_optional<'e, 'c, E>(self, executor: E) -> Result<Option<O>, Error>
    where
        'c: 'e,
        'q: 'e,
        O: 'e,
        A: 'e,
        E: 'e + Executor<'c, Database = DB>,
    {
        self.query
            .fetch_optional(RecordingExecutor::new(executor, self.span))
            .await
    }

    pub async fn fetch_all<'e, 'c, E>(self, executor: E) -> Result<Vec<O>, Error>
    where
        'c: 'e,
        'q: 'e,
        O: 'e,
        A: 'e,
        E: 'e + Executor<'c, Database = DB>,
    {
        self.query
            .fetch_all(RecordingExecutor::new(executor, self.span))
            .await
    }
}

impl<'q, DB: Database, O, A> Traced<QueryScalar<'q, DB, O, A>>
where
    O: Send + Unpin,
    A: 'q + IntoArguments<DB>,
    (O,): Send + Unpin + for<'r> sqlx::FromRow<'r, DB::Row>,
{
    pub async fn fetch_one<'e, 'c, E>(self, executor: E) -> Result<O, Error>
    where
        'c: 'e,
        'q: 'e,
        O: 'e,
        A: 'e,
        E: 'e + Executor<'c, Database = DB>,
    {
        self.query
            .fetch_one(RecordingExecutor::new(executor, self.span))
            .await
    }

    pub async fn fetch_optional<'e, 'c, E>(self, executor: E) -> Result<Option<O>, Error>
    where
        'c: 'e,
        'q: 'e,
        O: 'e,
        A: 'e,
        E: 'e + Executor<'c, Database = DB>,
    {
        self.query
            .fetch_optional(RecordingExecutor::new(executor, self.span))
            .await
    }

    pub async fn fetch_all<'e, 'c, E>(self, executor: E) -> Result<Vec<O>, Error>
    where
        'c: 'e,
        'q: 'e,
        O: 'e,
        A: 'e,
        E: 'e + Executor<'c, Database = DB>,
    {
        self.query
            .fetch_all(RecordingExecutor::new(executor, self.span))
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use mas_context::LogContext;
    use opentelemetry_semantic_conventions::attribute::DB_QUERY_TEXT;
    use sqlx::{
        PgConnection, PgPool, Postgres,
        encode::IsNull,
        error::BoxDynError,
        postgres::{PgArgumentBuffer, PgTypeInfo},
    };
    use tracing::{
        Subscriber,
        field::{Field, Visit},
        span::{Id, Record},
    };
    use tracing_subscriber::{
        layer::{Context, Layer, SubscriberExt},
        registry::Registry,
    };

    use crate::tracing::ExecuteExt;

    /// Collects every value recorded as `db.query.text` on any span.
    #[derive(Clone, Default)]
    struct QueryTextCollector(Arc<Mutex<Vec<String>>>);

    impl Visit for &QueryTextCollector {
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == DB_QUERY_TEXT {
                self.0.lock().unwrap().push(value.to_owned());
            }
        }

        fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
    }

    impl<S: Subscriber> Layer<S> for QueryTextCollector {
        fn on_record(&self, _id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
            values.record(&mut &*self);
        }
    }

    /// The SQL of a query with bound arguments should be recorded on the span,
    /// through both `fetch_optional` and `fetch_many`.
    #[sqlx::test]
    async fn test_query_text_recorded(pool: PgPool) {
        let collector = QueryTextCollector::default();
        let _guard = tracing::subscriber::set_default(Registry::default().with(collector.clone()));

        let span = tracing::info_span!("test", { DB_QUERY_TEXT } = tracing::field::Empty);
        let value: i32 = sqlx::query_scalar("SELECT $1::INT4")
            .bind(42_i32)
            .record(&span)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(value, 42);

        let span = tracing::info_span!("test", { DB_QUERY_TEXT } = tracing::field::Empty);
        let values: Vec<i32> = sqlx::query_scalar("SELECT UNNEST($1::INT4[])")
            .bind([1_i32, 2])
            .record(&span)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(values, [1, 2]);

        assert_eq!(
            *collector.0.lock().unwrap(),
            ["SELECT $1::INT4", "SELECT UNNEST($1::INT4[])"]
        );
    }

    /// Encodes as an error, to exercise the argument encoding failure path.
    struct FailingEncode;

    impl sqlx::Type<Postgres> for FailingEncode {
        fn type_info() -> PgTypeInfo {
            <i32 as sqlx::Type<Postgres>>::type_info()
        }
    }

    impl sqlx::Encode<'_, Postgres> for FailingEncode {
        fn encode_by_ref(&self, _buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
            Err("encoding failed".into())
        }
    }

    /// The SQL should be recorded on the span even if encoding the arguments
    /// fails.
    #[sqlx::test]
    async fn test_query_text_recorded_on_encode_error(pool: PgPool) {
        let collector = QueryTextCollector::default();
        let _guard = tracing::subscriber::set_default(Registry::default().with(collector.clone()));

        let span = tracing::info_span!("test", { DB_QUERY_TEXT } = tracing::field::Empty);
        let result = sqlx::query("SELECT $1::INT4")
            .bind(FailingEncode)
            .record(&span)
            .fetch_optional(&pool)
            .await;
        assert!(matches!(result, Err(sqlx::Error::Encode(_))));

        assert_eq!(*collector.0.lock().unwrap(), ["SELECT $1::INT4"]);
    }

    /// Tracing a query should not change whether its statement is cached on
    /// the connection.
    #[sqlx::test]
    async fn test_persistent_flag_kept(pool: PgPool) {
        async fn is_prepared(conn: &mut PgConnection, sql: &str) -> bool {
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_prepared_statements WHERE statement = $1)",
            )
            .bind(sql)
            .persistent(false)
            .fetch_one(conn)
            .await
            .unwrap()
        }

        let mut conn = pool.acquire().await.unwrap();

        let sql = "SELECT $1::INT4 AS persistent";
        sqlx::query(sql)
            .bind(1_i32)
            .traced()
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert!(is_prepared(&mut conn, sql).await);

        let sql = "SELECT $1::INT4 AS not_persistent";
        sqlx::query(sql)
            .bind(1_i32)
            .persistent(false)
            .traced()
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert!(!is_prepared(&mut conn, sql).await);
    }

    /// Each executed query should be counted (and timed) on the surrounding
    /// [`LogContext`].
    #[sqlx::test]
    async fn test_db_stats_recorded(pool: PgPool) {
        let log_context = LogContext::new("test");
        log_context
            .run(|| async {
                sqlx::query("SELECT 1")
                    .traced()
                    .fetch_one(&pool)
                    .await
                    .unwrap();

                sqlx::query("SELECT 1 FROM UNNEST(ARRAY[1, 2, 3])")
                    .traced()
                    .fetch_all(&pool)
                    .await
                    .unwrap();
            })
            .await;

        let stats = log_context.stats();
        assert_eq!(stats.db_queries, 2);
        assert_eq!(stats.db_rows_fetched, 4);
        assert!(stats.to_string().contains("queries: 2, fetched: 4"));
    }
}
