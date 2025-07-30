// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! A module containing the PostgreSQL implementation of the
//! [`QueueJobRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mas_data_model::Clock;
use mas_storage::queue::{Job, QueueJobRepository, Worker};
use opentelemetry_semantic_conventions::trace::DB_QUERY_TEXT;
use rand::RngCore;
use sqlx::PgConnection;
use tracing::Instrument;
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
    attempt: i32,
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

        let attempt = value.attempt.try_into().map_err(|e| {
            DatabaseInconsistencyError::on("queue_jobs")
                .column("attempt")
                .row(id)
                .source(e)
        })?;

        Ok(Self {
            id,
            queue_name,
            payload,
            metadata,
            attempt,
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
        name = "db.queue_job.schedule_later",
        fields(
            queue_job.id,
            queue_job.queue_name = queue_name,
            queue_job.scheduled_at = %scheduled_at,
            db.query.text,
        ),
        skip_all,
        err,
    )]
    async fn schedule_later(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        queue_name: &str,
        payload: serde_json::Value,
        metadata: serde_json::Value,
        scheduled_at: DateTime<Utc>,
        schedule_name: Option<&str>,
    ) -> Result<(), Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("queue_job.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO queue_jobs
                    (queue_job_id, queue_name, payload, metadata, created_at, scheduled_at, schedule_name, status)
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'scheduled')
            "#,
            Uuid::from(id),
            queue_name,
            payload,
            metadata,
            created_at,
            scheduled_at,
            schedule_name,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        // If there was a schedule name supplied, update the queue_schedules table
        if let Some(schedule_name) = schedule_name {
            let span = tracing::info_span!(
                "db.queue_job.schedule_later.update_schedules",
                { DB_QUERY_TEXT } = tracing::field::Empty,
            );

            let res = sqlx::query!(
                r#"
                    UPDATE queue_schedules
                    SET last_scheduled_at = $1,
                        last_scheduled_job_id = $2
                    WHERE schedule_name = $3
                "#,
                scheduled_at,
                Uuid::from(id),
                schedule_name,
            )
            .record(&span)
            .execute(&mut *self.conn)
            .instrument(span)
            .await?;

            DatabaseError::ensure_affected_rows(&res, 1)?;
        }

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
                    queue_jobs.metadata,
                    queue_jobs.attempt
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

    #[tracing::instrument(
        name = "db.queue_job.mark_as_failed",
        skip_all,
        fields(
            db.query.text,
            job.id = %id,
        ),
        err
    )]
    async fn mark_as_failed(
        &mut self,
        clock: &dyn Clock,
        id: Ulid,
        reason: &str,
    ) -> Result<(), Self::Error> {
        let now = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE queue_jobs
                SET
                    status = 'failed',
                    failed_at = $1,
                    failed_reason = $2
                WHERE
                    queue_job_id = $3
                    AND status = 'running'
            "#,
            now,
            reason,
            Uuid::from(id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_job.retry",
        skip_all,
        fields(
            db.query.text,
            job.id = %id,
        ),
        err
    )]
    async fn retry(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        id: Ulid,
        delay: Duration,
    ) -> Result<(), Self::Error> {
        let now = clock.now();
        let scheduled_at = now + delay;
        let new_id = Ulid::from_datetime_with_source(now.into(), rng);

        let span = tracing::info_span!(
            "db.queue_job.retry.insert_job",
            { DB_QUERY_TEXT } = tracing::field::Empty
        );
        // Create a new job with the same payload and metadata, but a new ID and
        // increment the attempt
        // We make sure we do this only for 'failed' jobs
        let res = sqlx::query!(
            r#"
                INSERT INTO queue_jobs
                    (queue_job_id, queue_name, payload, metadata, created_at,
                     attempt, scheduled_at, schedule_name, status)
                SELECT $1, queue_name, payload, metadata, $2, attempt + 1, $3, schedule_name, 'scheduled'
                FROM queue_jobs
                WHERE queue_job_id = $4
                  AND status = 'failed'
            "#,
            Uuid::from(new_id),
            now,
            scheduled_at,
            Uuid::from(id),
        )
        .record(&span)
        .execute(&mut *self.conn)
        .instrument(span)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        // If that job was referenced by a schedule, update the schedule
        let span = tracing::info_span!(
            "db.queue_job.retry.update_schedule",
            { DB_QUERY_TEXT } = tracing::field::Empty
        );
        sqlx::query!(
            r#"
                UPDATE queue_schedules
                SET last_scheduled_at = $1,
                    last_scheduled_job_id = $2
                WHERE last_scheduled_job_id = $3
            "#,
            scheduled_at,
            Uuid::from(new_id),
            Uuid::from(id),
        )
        .record(&span)
        .execute(&mut *self.conn)
        .instrument(span)
        .await?;

        // Update the old job to point to the new attempt
        let span = tracing::info_span!(
            "db.queue_job.retry.update_old_job",
            { DB_QUERY_TEXT } = tracing::field::Empty
        );
        let res = sqlx::query!(
            r#"
                UPDATE queue_jobs
                SET next_attempt_id = $1
                WHERE queue_job_id = $2
            "#,
            Uuid::from(new_id),
            Uuid::from(id),
        )
        .record(&span)
        .execute(&mut *self.conn)
        .instrument(span)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_job.schedule_available_jobs",
        skip_all,
        fields(
            db.query.text,
        ),
        err
    )]
    async fn schedule_available_jobs(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error> {
        let now = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE queue_jobs
                SET status = 'available'
                WHERE
                    status = 'scheduled'
                    AND scheduled_at <= $1
            "#,
            now,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let count = res.rows_affected();
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }
}
