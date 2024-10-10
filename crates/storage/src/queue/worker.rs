// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Repository to interact with workers in the job queue

use async_trait::async_trait;
use chrono::Duration;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{repository_impl, Clock};

/// A worker is an entity which can execute jobs.
pub struct Worker {
    /// The ID of the worker.
    pub id: Ulid,
}

/// A [`QueueWorkerRepository`] is used to schedule jobs to be executed by a
/// worker.
#[async_trait]
pub trait QueueWorkerRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Register a new worker.
    ///
    /// Returns a reference to the worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn register(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
    ) -> Result<Worker, Self::Error>;

    /// Send a heartbeat for the given worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails or if the worker was
    /// shutdown.
    async fn heartbeat(&mut self, clock: &dyn Clock, worker: &Worker) -> Result<(), Self::Error>;

    /// Mark the given worker as shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn shutdown(&mut self, clock: &dyn Clock, worker: Worker) -> Result<(), Self::Error>;

    /// Find dead workers and shut them down.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn shutdown_dead_workers(
        &mut self,
        clock: &dyn Clock,
        threshold: Duration,
    ) -> Result<(), Self::Error>;

    /// Remove the leader lease if it is expired, sending a notification to
    /// trigger a new leader election.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn remove_leader_lease_if_expired(
        &mut self,
        clock: &dyn Clock,
    ) -> Result<(), Self::Error>;

    /// Try to get the leader lease, renewing it if we already have it
    ///
    /// Returns `true` if we got the leader lease, `false` if we didn't
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn try_get_leader_lease(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
    ) -> Result<bool, Self::Error>;
}

repository_impl!(QueueWorkerRepository:
    async fn register(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
    ) -> Result<Worker, Self::Error>;

    async fn heartbeat(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
    ) -> Result<(), Self::Error>;

    async fn shutdown(
        &mut self,
        clock: &dyn Clock,
        worker: Worker,
    ) -> Result<(), Self::Error>;

    async fn shutdown_dead_workers(
        &mut self,
        clock: &dyn Clock,
        threshold: Duration,
    ) -> Result<(), Self::Error>;

    async fn remove_leader_lease_if_expired(
        &mut self,
        clock: &dyn Clock,
    ) -> Result<(), Self::Error>;

    async fn try_get_leader_lease(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
    ) -> Result<bool, Self::Error>;
);
