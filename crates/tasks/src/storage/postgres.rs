// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{convert::TryInto, marker::PhantomData, ops::Add, sync::Arc, time::Duration};

use apalis_core::{
    error::JobStreamError,
    job::{Job, JobId, JobStreamResult},
    request::JobRequest,
    storage::{StorageError, StorageResult, StorageWorkerPulse},
    utils::Timer,
    worker::WorkerId,
};
use async_stream::try_stream;
use chrono::{DateTime, Utc};
use event_listener::Event;
use futures_lite::{Stream, StreamExt};
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{postgres::PgListener, PgPool, Pool, Postgres, Row};
use tokio::task::JoinHandle;

use super::SqlJobRequest;

pub struct StorageFactory {
    pool: PgPool,
    event: Arc<Event>,
}

impl StorageFactory {
    pub fn new(pool: Pool<Postgres>) -> Self {
        StorageFactory {
            pool,
            event: Arc::new(Event::new()),
        }
    }

    pub async fn listen(self) -> Result<JoinHandle<()>, sqlx::Error> {
        let mut listener = PgListener::connect_with(&self.pool).await?;
        listener.listen("apalis::job").await?;

        let handle = tokio::spawn(async move {
            loop {
                let notification = listener.recv().await.expect("Failed to poll notification");
                self.event.notify(usize::MAX);
                tracing::debug!(?notification, "Broadcast notification");
            }
        });

        Ok(handle)
    }

    pub fn build<T>(&self) -> Storage<T> {
        Storage {
            pool: self.pool.clone(),
            event: self.event.clone(),
            job_type: PhantomData,
        }
    }
}

/// Represents a [`apalis_core::storage::Storage`] that persists to Postgres
#[derive(Debug)]
pub struct Storage<T> {
    pool: PgPool,
    event: Arc<Event>,
    job_type: PhantomData<T>,
}

impl<T> Clone for Storage<T> {
    fn clone(&self) -> Self {
        Storage {
            pool: self.pool.clone(),
            event: self.event.clone(),
            job_type: PhantomData,
        }
    }
}

impl<T: DeserializeOwned + Send + Unpin + Job> Storage<T> {
    fn stream_jobs(
        &self,
        worker_id: &WorkerId,
        interval: Duration,
        buffer_size: usize,
    ) -> impl Stream<Item = Result<JobRequest<T>, JobStreamError>> {
        let pool = self.pool.clone();
        let sleeper = apalis_core::utils::timer::TokioTimer;
        let worker_id = worker_id.clone();
        let event = self.event.clone();
        try_stream! {
            loop {
                // Wait for a notification or a timeout
                let listener = event.listen();
                let interval = sleeper.sleep(interval);
                futures_lite::future::race(interval, listener).await;

                let tx = pool.clone();
                let job_type = T::NAME;
                let fetch_query = "SELECT * FROM apalis.get_jobs($1, $2, $3);";
                let jobs: Vec<SqlJobRequest<T>> = sqlx::query_as(fetch_query)
                    .bind(worker_id.name())
                    .bind(job_type)
                    // https://docs.rs/sqlx/latest/sqlx/postgres/types/index.html
                    .bind(i32::try_from(buffer_size).map_err(|e| JobStreamError::BrokenPipe(Box::from(e)))?)
                    .fetch_all(&tx)
                    .await.map_err(|e| JobStreamError::BrokenPipe(Box::from(e)))?;
                for job in jobs {
                    yield job.into()
                }
            }
        }
    }

    async fn keep_alive_at<Service>(
        &mut self,
        worker_id: &WorkerId,
        last_seen: DateTime<Utc>,
    ) -> StorageResult<()> {
        let pool = self.pool.clone();

        let worker_type = T::NAME;
        let storage_name = std::any::type_name::<Self>();
        let query = "INSERT INTO apalis.workers (id, worker_type, storage_name, layers, last_seen)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (id) DO 
                   UPDATE SET last_seen = EXCLUDED.last_seen";
        sqlx::query(query)
            .bind(worker_id.name())
            .bind(worker_type)
            .bind(storage_name)
            .bind(std::any::type_name::<Service>())
            .bind(last_seen)
            .execute(&pool)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl<T> apalis_core::storage::Storage for Storage<T>
where
    T: Job + Serialize + DeserializeOwned + Send + 'static + Unpin + Sync,
{
    type Output = T;

    /// Push a job to Postgres [Storage]
    ///
    /// # SQL Example
    ///
    /// ```sql
    /// SELECT apalis.push_job(job_type::text, job::json);
    /// ```
    async fn push(&mut self, job: Self::Output) -> StorageResult<JobId> {
        let id = JobId::new();
        let query = "INSERT INTO apalis.jobs VALUES ($1, $2, $3, 'Pending', 0, 25, NOW() , NULL, NULL, NULL, NULL)";
        let pool = self.pool.clone();
        let job = serde_json::to_value(&job).map_err(|e| StorageError::Parse(Box::from(e)))?;
        let job_type = T::NAME;
        sqlx::query(query)
            .bind(job)
            .bind(id.to_string())
            .bind(job_type)
            .execute(&pool)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(id)
    }

    async fn schedule(
        &mut self,
        job: Self::Output,
        on: chrono::DateTime<Utc>,
    ) -> StorageResult<JobId> {
        let query =
            "INSERT INTO apalis.jobs VALUES ($1, $2, $3, 'Pending', 0, 25, $4, NULL, NULL, NULL, NULL)";

        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| StorageError::Connection(Box::from(e)))?;

        let id = JobId::new();
        let job = serde_json::to_value(&job).map_err(|e| StorageError::Parse(Box::from(e)))?;
        let job_type = T::NAME;
        sqlx::query(query)
            .bind(job)
            .bind(id.to_string())
            .bind(job_type)
            .bind(on)
            .execute(&mut *conn)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(id)
    }

    async fn fetch_by_id(&self, job_id: &JobId) -> StorageResult<Option<JobRequest<Self::Output>>> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| StorageError::Connection(Box::from(e)))?;

        let fetch_query = "SELECT * FROM apalis.jobs WHERE id = $1";
        let res: Option<SqlJobRequest<T>> = sqlx::query_as(fetch_query)
            .bind(job_id.to_string())
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(res.map(Into::into))
    }

    async fn heartbeat(&mut self, pulse: StorageWorkerPulse) -> StorageResult<bool> {
        match pulse {
            StorageWorkerPulse::EnqueueScheduled { count: _ } => {
                // Ideally jobs are queue via run_at. So this is not necessary
                Ok(true)
            }

            // Worker not seen in 5 minutes yet has running jobs
            StorageWorkerPulse::ReenqueueOrphaned { count, .. } => {
                let job_type = T::NAME;
                let mut conn = self
                    .pool
                    .acquire()
                    .await
                    .map_err(|e| StorageError::Database(Box::from(e)))?;
                let query = "UPDATE apalis.jobs 
                            SET status = 'Pending', done_at = NULL, lock_by = NULL, lock_at = NULL, last_error ='Job was abandoned'
                            WHERE id in 
                                (SELECT jobs.id from apalis.jobs INNER join apalis.workers ON lock_by = workers.id 
                                    WHERE status = 'Running' AND workers.last_seen < NOW() - INTERVAL '5 minutes'
                                    AND workers.worker_type = $1 ORDER BY lock_at ASC LIMIT $2);";
                sqlx::query(query)
                    .bind(job_type)
                    .bind(count)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| StorageError::Database(Box::from(e)))?;
                Ok(true)
            }

            _ => unimplemented!(),
        }
    }

    async fn kill(&mut self, worker_id: &WorkerId, job_id: &JobId) -> StorageResult<()> {
        let pool = self.pool.clone();

        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| StorageError::Connection(Box::from(e)))?;
        let query =
                "UPDATE apalis.jobs SET status = 'Killed', done_at = now() WHERE id = $1 AND lock_by = $2";
        sqlx::query(query)
            .bind(job_id.to_string())
            .bind(worker_id.name())
            .execute(&mut *conn)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(())
    }

    /// Puts the job instantly back into the queue
    /// Another [Worker] may consume
    async fn retry(&mut self, worker_id: &WorkerId, job_id: &JobId) -> StorageResult<()> {
        let pool = self.pool.clone();

        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| StorageError::Connection(Box::from(e)))?;
        let query =
                "UPDATE apalis.jobs SET status = 'Pending', done_at = NULL, lock_by = NULL WHERE id = $1 AND lock_by = $2";
        sqlx::query(query)
            .bind(job_id.to_string())
            .bind(worker_id.name())
            .execute(&mut *conn)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(())
    }

    fn consume(
        &mut self,
        worker_id: &WorkerId,
        interval: Duration,
        buffer_size: usize,
    ) -> JobStreamResult<T> {
        Box::pin(
            self.stream_jobs(worker_id, interval, buffer_size)
                .map(|r| r.map(Some)),
        )
    }
    async fn len(&self) -> StorageResult<i64> {
        let pool = self.pool.clone();
        let query = "SELECT COUNT(*) AS count FROM apalis.jobs WHERE status = 'Pending'";
        let record = sqlx::query(query)
            .fetch_one(&pool)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(record
            .try_get("count")
            .map_err(|e| StorageError::Database(Box::from(e)))?)
    }
    async fn ack(&mut self, worker_id: &WorkerId, job_id: &JobId) -> StorageResult<()> {
        let pool = self.pool.clone();
        let query =
                "UPDATE apalis.jobs SET status = 'Done', done_at = now() WHERE id = $1 AND lock_by = $2";
        sqlx::query(query)
            .bind(job_id.to_string())
            .bind(worker_id.name())
            .execute(&pool)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(())
    }

    async fn reschedule(&mut self, job: &JobRequest<T>, wait: Duration) -> StorageResult<()> {
        let pool = self.pool.clone();
        let job_id = job.id();

        let wait: i64 = wait
            .as_secs()
            .try_into()
            .map_err(|e| StorageError::Database(Box::new(e)))?;
        let wait = chrono::Duration::microseconds(wait * 1000 * 1000);
        // TODO: should we use a clock here?
        #[allow(clippy::disallowed_methods)]
        let run_at = Utc::now().add(wait);

        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| StorageError::Connection(Box::from(e)))?;
        let query =
                "UPDATE apalis.jobs SET status = 'Pending', done_at = NULL, lock_by = NULL, lock_at = NULL, run_at = $2 WHERE id = $1";
        sqlx::query(query)
            .bind(job_id.to_string())
            .bind(run_at)
            .execute(&mut *conn)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(())
    }

    async fn update_by_id(
        &self,
        job_id: &JobId,
        job: &JobRequest<Self::Output>,
    ) -> StorageResult<()> {
        let pool = self.pool.clone();
        let status = job.status().as_ref();
        let attempts = job.attempts();
        let done_at = *job.done_at();
        let lock_by = job.lock_by().clone();
        let lock_at = *job.lock_at();
        let last_error = job.last_error().clone();

        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| StorageError::Connection(Box::from(e)))?;
        let query =
                "UPDATE apalis.jobs SET status = $1, attempts = $2, done_at = $3, lock_by = $4, lock_at = $5, last_error = $6 WHERE id = $7";
        sqlx::query(query)
            .bind(status.to_owned())
            .bind(attempts)
            .bind(done_at)
            .bind(lock_by.as_ref().map(WorkerId::name))
            .bind(lock_at)
            .bind(last_error)
            .bind(job_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(|e| StorageError::Database(Box::from(e)))?;
        Ok(())
    }

    async fn keep_alive<Service>(&mut self, worker_id: &WorkerId) -> StorageResult<()> {
        #[allow(clippy::disallowed_methods)]
        let now = Utc::now();

        self.keep_alive_at::<Service>(worker_id, now).await
    }
}
