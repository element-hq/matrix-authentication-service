// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Repository to schedule persistent jobs.

use std::{num::ParseIntError, ops::Deref};

pub use apalis_core::job::{Job, JobId};
use async_trait::async_trait;
use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::repository_impl;

/// A job submission to be scheduled through the repository.
pub struct JobSubmission {
    name: &'static str,
    payload: Value,
}

#[derive(Serialize, Deserialize)]
struct SerializableSpanContext {
    trace_id: String,
    span_id: String,
    trace_flags: u8,
}

impl From<&SpanContext> for SerializableSpanContext {
    fn from(value: &SpanContext) -> Self {
        Self {
            trace_id: value.trace_id().to_string(),
            span_id: value.span_id().to_string(),
            trace_flags: value.trace_flags().to_u8(),
        }
    }
}

impl TryFrom<&SerializableSpanContext> for SpanContext {
    type Error = ParseIntError;

    fn try_from(value: &SerializableSpanContext) -> Result<Self, Self::Error> {
        Ok(SpanContext::new(
            TraceId::from_hex(&value.trace_id)?,
            SpanId::from_hex(&value.span_id)?,
            TraceFlags::new(value.trace_flags),
            // XXX: is that fine?
            true,
            TraceState::default(),
        ))
    }
}

/// A wrapper for [`Job`] which adds the span context in the payload.
#[derive(Serialize, Deserialize)]
pub struct JobWithSpanContext<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    span_context: Option<SerializableSpanContext>,

    #[serde(flatten)]
    payload: T,
}

impl<J> From<J> for JobWithSpanContext<J> {
    fn from(payload: J) -> Self {
        Self {
            span_context: None,
            payload,
        }
    }
}

impl<J: Job> Job for JobWithSpanContext<J> {
    const NAME: &'static str = J::NAME;
}

impl<T> Deref for JobWithSpanContext<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl<T> JobWithSpanContext<T> {
    /// Get the span context of the job.
    ///
    /// # Returns
    ///
    /// Returns [`None`] if the job has no span context, or if the span context
    /// is invalid.
    #[must_use]
    pub fn span_context(&self) -> Option<SpanContext> {
        self.span_context
            .as_ref()
            .and_then(|ctx| ctx.try_into().ok())
    }
}

impl JobSubmission {
    /// Create a new job submission out of a [`Job`].
    ///
    /// # Panics
    ///
    /// Panics if the job cannot be serialized.
    #[must_use]
    pub fn new<J: Job + Serialize>(job: J) -> Self {
        let payload = serde_json::to_value(job).expect("Could not serialize job");

        Self {
            name: J::NAME,
            payload,
        }
    }

    /// Create a new job submission out of a [`Job`] and a [`SpanContext`].
    ///
    /// # Panics
    ///
    /// Panics if the job cannot be serialized.
    #[must_use]
    pub fn new_with_span_context<J: Job + Serialize>(job: J, span_context: &SpanContext) -> Self {
        // Serialize the span context alongside the job.
        let span_context = SerializableSpanContext::from(span_context);

        Self::new(JobWithSpanContext {
            payload: job,
            span_context: Some(span_context),
        })
    }

    /// The name of the job.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The payload of the job.
    #[must_use]
    pub fn payload(&self) -> &Value {
        &self.payload
    }
}

/// A [`JobRepository`] is used to schedule jobs to be executed by a worker.
#[async_trait]
pub trait JobRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Schedule a job submission to be executed at a later time.
    ///
    /// # Parameters
    ///
    /// * `submission` - The job to schedule.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn schedule_submission(
        &mut self,
        submission: JobSubmission,
    ) -> Result<JobId, Self::Error>;
}

repository_impl!(JobRepository:
    async fn schedule_submission(&mut self, submission: JobSubmission) -> Result<JobId, Self::Error>;
);

/// An extension trait for [`JobRepository`] to schedule jobs directly.
#[async_trait]
pub trait JobRepositoryExt {
    /// The error type returned by the repository.
    type Error;

    /// Schedule a job to be executed at a later time.
    ///
    /// # Parameters
    ///
    /// * `job` - The job to schedule.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn schedule_job<J: Job + Serialize + Send>(
        &mut self,
        job: J,
    ) -> Result<JobId, Self::Error>;
}

#[async_trait]
impl<T> JobRepositoryExt for T
where
    T: JobRepository + ?Sized,
{
    type Error = T::Error;

    #[tracing::instrument(
        name = "db.job.schedule_job",
        skip_all,
        fields(
            job.name = J::NAME,
        ),
    )]
    async fn schedule_job<J: Job + Serialize + Send>(
        &mut self,
        job: J,
    ) -> Result<JobId, Self::Error> {
        let span = tracing::Span::current();
        let ctx = span.context();
        let span = ctx.span();
        let span_context = span.span_context();

        self.schedule_submission(JobSubmission::new_with_span_context(job, span_context))
            .await
    }
}
