// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Repository to interact with jobs in the job queue

use async_trait::async_trait;
use rand_core::RngCore;
use ulid::Ulid;

use super::Worker;
use crate::{repository_impl, Clock};

enum JobState {
    /// The job is available to be picked up by a worker
    Available,

    /// The job is currently being processed by a worker
    Running,

    /// The job has been completed
    Completed,

    /// The worker running the job was lost
    Lost,
}

/// Represents a job in the job queue
pub struct Job {
    /// The ID of the job
    pub id: Ulid,
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

    /// Get and lock a batch of jobs that are ready to be executed.
    /// This will transition them to a [`JobState::Running`] state.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn get_available(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
        queues: &[&str],
        max_count: usize,
    ) -> Result<Vec<Job>, Self::Error>;

    /// Mark the given job as completed.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn mark_completed(&mut self, clock: &dyn Clock, job: Job) -> Result<(), Self::Error>;
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

    async fn get_available(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
        queues: &[&str],
        max_count: usize,
    ) -> Result<Vec<Job>, Self::Error>;

    async fn mark_completed(&mut self, clock: &dyn Clock, job: Job) -> Result<(), Self::Error>;
);
