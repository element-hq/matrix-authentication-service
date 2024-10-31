// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! A module containing the PostgreSQL implementation of the
//! [`QueueJobRepository`].

use async_trait::async_trait;
use mas_storage::{
    queue::{Job, QueueJobRepository, Worker},
    Clock,
};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, DatabaseInconsistencyError, ExecuteExt};

/// An implementation of [`QueueJobRepository`] for a PostgreSQL connection.
pub struct PgQueueJobRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgQueueJobRepository<'c> {
    /// Create a new [`PgQueueJobRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct JobReservationResult {
    queue_job_id: Uuid,
    queue_name: String,
    payload: serde_json::Value,
    metadata: serde_json::Value,
}

impl TryFrom<JobReservationResult> for Job {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: JobReservationResult) -> Result<Self, Self::Error> {
        let id = value.queue_job_id.into();
        let queue_name = value.queue_name;
        let payload = value.payload;

        let metadata = serde_json::from_value(value.metadata).map_err(|e| {
            DatabaseInconsistencyError::on("queue_jobs")
                .column("metadata")
                .row(id)
                .source(e)
        })?;

        Ok(Self {
            id,
            queue_name,
            payload,
            metadata,
        })
    }
}

#[async_trait]
impl QueueJobRepository for PgQueueJobRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.queue_job.schedule",
        fields(
            queue_job.id,
            queue_job.queue_name = queue_name,
            db.query.text,
        ),
        skip_all,
        err,
    )]
    async fn schedule(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        queue_name: &str,
        payload: serde_json::Value,
        metadata: serde_json::Value,
    ) -> Result<(), Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("queue_job.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO queue_jobs
                    (queue_job_id, queue_name, payload, metadata, created_at)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            queue_name,
            payload,
            metadata,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_job.reserve",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn reserve(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
        queues: &[&str],
        count: usize,
    ) -> Result<Vec<Job>, Self::Error> {
        let now = clock.now();
        let max_count = i64::try_from(count).unwrap_or(i64::MAX);
        let queues: Vec<String> = queues.iter().map(|&s| s.to_owned()).collect();
        let results = sqlx::query_as!(
            JobReservationResult,
            r#"
                -- We first grab a few jobs that are available,
                -- using a FOR UPDATE SKIP LOCKED so that this can be run concurrently
                -- and we don't get multiple workers grabbing the same jobs
                WITH locked_jobs AS (
                    SELECT queue_job_id
                    FROM queue_jobs
                    WHERE
                        status = 'available'
                        AND queue_name = ANY($1)
                    ORDER BY queue_job_id ASC
                    LIMIT $2
                    FOR UPDATE
                    SKIP LOCKED
                )
                -- then we update the status of those jobs to 'running', returning the job details
                UPDATE queue_jobs
                SET status = 'running', started_at = $3, started_by = $4
                FROM locked_jobs
                WHERE queue_jobs.queue_job_id = locked_jobs.queue_job_id
                RETURNING
                    queue_jobs.queue_job_id,
                    queue_jobs.queue_name,
                    queue_jobs.payload,
                    queue_jobs.metadata
            "#,
            &queues,
            max_count,
            now,
            Uuid::from(worker.id),
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        let jobs = results
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(jobs)
    }

    #[tracing::instrument(
        name = "db.queue_job.mark_as_completed",
        skip_all,
        fields(
            db.query.text,
            job.id = %id,
        ),
        err,
    )]
    async fn mark_as_completed(&mut self, clock: &dyn Clock, id: Ulid) -> Result<(), Self::Error> {
        let now = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE queue_jobs
                SET status = 'completed', completed_at = $1
                WHERE queue_job_id = $2 AND status = 'running'
            "#,
            now,
            Uuid::from(id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(())
    }
}
