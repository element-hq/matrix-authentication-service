// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Repository to interact with jobs in the job queue

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use opentelemetry::trace::TraceContextExt;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use ulid::Ulid;

use super::Worker;
use crate::{Clock, repository_impl};

/// Represents a job in the job queue
pub struct Job {
    /// The ID of the job
    pub id: Ulid,

    /// The queue on which the job was placed
    pub queue_name: String,

    /// The payload of the job
    pub payload: serde_json::Value,

    /// Arbitrary metadata about the job
    pub metadata: JobMetadata,

    /// Which attempt it is
    pub attempt: usize,
}

/// Metadata stored alongside the job
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct JobMetadata {
    #[serde(default)]
    trace_id: String,

    #[serde(default)]
    span_id: String,

    #[serde(default)]
    trace_flags: u8,
}

impl JobMetadata {
    fn new(span_context: &opentelemetry::trace::SpanContext) -> Self {
        Self {
            trace_id: span_context.trace_id().to_string(),
            span_id: span_context.span_id().to_string(),
            trace_flags: span_context.trace_flags().to_u8(),
        }
    }

    /// Get the [`opentelemetry::trace::SpanContext`] from this [`JobMetadata`]
    #[must_use]
    pub fn span_context(&self) -> opentelemetry::trace::SpanContext {
        use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId, TraceState};
        SpanContext::new(
            TraceId::from_hex(&self.trace_id).unwrap_or(TraceId::INVALID),
            SpanId::from_hex(&self.span_id).unwrap_or(SpanId::INVALID),
            TraceFlags::new(self.trace_flags),
            // Trace context is remote, as it comes from another service/from the database
            true,
            TraceState::NONE,
        )
    }
}

/// A trait that represents a job which can be inserted into a queue
pub trait InsertableJob: Serialize + Send {
    /// The name of the queue this job belongs to
    const QUEUE_NAME: &'static str;
}

/// A [`QueueJobRepository`] is used to schedule jobs to be executed by a
/// worker.
#[async_trait]
pub trait QueueJobRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Schedule a job to be executed as soon as possible by a worker.
    ///
    /// # Parameters
    ///
    /// * `rng` - The random number generator used to generate a new job ID
    /// * `clock` - The clock used to generate timestamps
    /// * `queue_name` - The name of the queue to schedule the job on
    /// * `payload` - The payload of the job
    /// * `metadata` - Arbitrary metadata about the job scheduled immediately.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn schedule(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        queue_name: &str,
        payload: serde_json::Value,
        metadata: serde_json::Value,
    ) -> Result<(), Self::Error>;

    /// Schedule a job to be executed at a later date by a worker.
    ///
    /// # Parameters
    ///
    /// * `rng` - The random number generator used to generate a new job ID
    /// * `clock` - The clock used to generate timestamps
    /// * `queue_name` - The name of the queue to schedule the job on
    /// * `payload` - The payload of the job
    /// * `metadata` - Arbitrary metadata about the job scheduled immediately.
    /// * `scheduled_at` - The date and time to schedule the job for
    /// * `schedule_name` - The name of the recurring schedule which scheduled
    ///   this job
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    #[allow(clippy::too_many_arguments)]
    async fn schedule_later(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        queue_name: &str,
        payload: serde_json::Value,
        metadata: serde_json::Value,
        scheduled_at: DateTime<Utc>,
        schedule_name: Option<&str>,
    ) -> Result<(), Self::Error>;

    /// Reserve multiple jobs from multiple queues
    ///
    /// # Parameters
    ///
    /// * `clock` - The clock used to generate timestamps
    /// * `worker` - The worker that is reserving the jobs
    /// * `queues` - The queues to reserve jobs from
    /// * `count` - The number of jobs to reserve
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn reserve(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
        queues: &[&str],
        count: usize,
    ) -> Result<Vec<Job>, Self::Error>;

    /// Mark a job as completed
    ///
    /// # Parameters
    ///
    /// * `clock` - The clock used to generate timestamps
    /// * `id` - The ID of the job to mark as completed
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn mark_as_completed(&mut self, clock: &dyn Clock, id: Ulid) -> Result<(), Self::Error>;

    /// Marks a job as failed.
    ///
    /// # Parameters
    ///
    /// * `clock` - The clock used to generate timestamps
    /// * `id` - The ID of the job to mark as failed
    /// * `reason` - The reason for the failure
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn mark_as_failed(
        &mut self,
        clock: &dyn Clock,
        id: Ulid,
        reason: &str,
    ) -> Result<(), Self::Error>;

    /// Retry a job.
    ///
    /// # Parameters
    ///
    /// * `rng` - The random number generator used to generate a new job ID
    /// * `clock` - The clock used to generate timestamps
    /// * `id` - The ID of the job to reschedule
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn retry(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        id: Ulid,
        delay: Duration,
    ) -> Result<(), Self::Error>;

    /// Mark all scheduled jobs past their scheduled date as available to be
    /// executed.
    ///
    /// Returns the number of jobs that were marked as available.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn schedule_available_jobs(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error>;
}

repository_impl!(QueueJobRepository:
    async fn schedule(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        queue_name: &str,
        payload: serde_json::Value,
        metadata: serde_json::Value,
    ) -> Result<(), Self::Error>;

    async fn schedule_later(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        queue_name: &str,
        payload: serde_json::Value,
        metadata: serde_json::Value,
        scheduled_at: DateTime<Utc>,
        schedule_name: Option<&str>,
    ) -> Result<(), Self::Error>;

    async fn reserve(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
        queues: &[&str],
        count: usize,
    ) -> Result<Vec<Job>, Self::Error>;

    async fn mark_as_completed(&mut self, clock: &dyn Clock, id: Ulid) -> Result<(), Self::Error>;

    async fn mark_as_failed(&mut self,
        clock: &dyn Clock,
        id: Ulid,
        reason: &str,
    ) -> Result<(), Self::Error>;

    async fn retry(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        id: Ulid,
        delay: Duration,
    ) -> Result<(), Self::Error>;

    async fn schedule_available_jobs(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error>;
);

/// Extension trait for [`QueueJobRepository`] to help adding a job to the queue
/// through the [`InsertableJob`] trait. This isn't in the
/// [`QueueJobRepository`] trait to keep it object safe.
#[async_trait]
pub trait QueueJobRepositoryExt: QueueJobRepository {
    /// Schedule a job to be executed as soon as possible by a worker.
    ///
    /// # Parameters
    ///
    /// * `rng` - The random number generator used to generate a new job ID
    /// * `clock` - The clock used to generate timestamps
    /// * `job` - The job to schedule
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn schedule_job<J: InsertableJob>(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        job: J,
    ) -> Result<(), Self::Error>;

    /// Schedule a job to be executed at a later date by a worker.
    ///
    /// # Parameters
    ///
    /// * `rng` - The random number generator used to generate a new job ID
    /// * `clock` - The clock used to generate timestamps
    /// * `job` - The job to schedule
    /// * `scheduled_at` - The date and time to schedule the job for
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn schedule_job_later<J: InsertableJob>(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        job: J,
        scheduled_at: DateTime<Utc>,
    ) -> Result<(), Self::Error>;
}

#[async_trait]
impl<T> QueueJobRepositoryExt for T
where
    T: QueueJobRepository,
{
    #[tracing::instrument(
        name = "db.queue_job.schedule_job",
        fields(
            queue_job.queue_name = J::QUEUE_NAME,
        ),
        skip_all,
    )]
    async fn schedule_job<J: InsertableJob>(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        job: J,
    ) -> Result<(), Self::Error> {
        // Grab the span context from the current span
        let span = tracing::Span::current();
        let ctx = span.context();
        let span = ctx.span();
        let span_context = span.span_context();

        let metadata = JobMetadata::new(span_context);
        let metadata = serde_json::to_value(metadata).expect("Could not serialize metadata");

        let payload = serde_json::to_value(job).expect("Could not serialize job");
        self.schedule(rng, clock, J::QUEUE_NAME, payload, metadata)
            .await
    }

    #[tracing::instrument(
        name = "db.queue_job.schedule_job_later",
        fields(
            queue_job.queue_name = J::QUEUE_NAME,
        ),
        skip_all,
    )]
    async fn schedule_job_later<J: InsertableJob>(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        job: J,
        scheduled_at: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        // Grab the span context from the current span
        let span = tracing::Span::current();
        let ctx = span.context();
        let span = ctx.span();
        let span_context = span.span_context();

        let metadata = JobMetadata::new(span_context);
        let metadata = serde_json::to_value(metadata).expect("Could not serialize metadata");

        let payload = serde_json::to_value(job).expect("Could not serialize job");
        self.schedule_later(
            rng,
            clock,
            J::QUEUE_NAME,
            payload,
            metadata,
            scheduled_at,
            None,
        )
        .await
    }
}
