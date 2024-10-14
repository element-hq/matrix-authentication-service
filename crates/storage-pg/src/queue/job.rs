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

use crate::{DatabaseError, ExecuteExt};

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

#[async_trait]
impl<'c> QueueJobRepository for PgQueueJobRepository<'c> {
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
        name = "db.queue_job.get_available",
        fields(
            db.query.text,
        ),
        skip_all,
        err,
    )]
    async fn get_available(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
        queues: &[&str],
        max_count: usize,
    ) -> Result<Vec<Job>, Self::Error> {
        let now = clock.now();
        let max_count = i64::try_from(max_count).unwrap_or(i64::MAX);
        let queues: Vec<String> = queues.iter().map(|&s| s.to_owned()).collect();
        sqlx::query!(
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

        todo!()
    }

    #[tracing::instrument(
        name = "db.queue_job.mark_completed",
        fields(
            queue_job.id = %job.id,
            db.query.text,
        ),
        skip_all,
        err,
    )]
    async fn mark_completed(&mut self, clock: &dyn Clock, job: Job) -> Result<(), Self::Error> {
        let _ = clock;
        let _ = job;
        todo!()
    }
}
