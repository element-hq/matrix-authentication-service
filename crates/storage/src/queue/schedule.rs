// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Repository to interact with recurrent scheduled jobs in the job queue

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::repository_impl;

/// [`QueueScheduleRepository::list`] returns a list of [`ScheduleStatus`],
/// which has the name of the schedule and infos about its last run
pub struct ScheduleStatus {
    /// Name of the schedule, uniquely identifying it
    pub schedule_name: String,
    /// When the schedule was last run
    pub last_scheduled_at: Option<DateTime<Utc>>,
    /// Did the last job on this schedule finish? (successfully or not)
    pub last_scheduled_job_completed: Option<bool>,
}

/// A [`QueueScheduleRepository`] is used to interact with recurrent scheduled
/// jobs in the job queue.
#[async_trait]
pub trait QueueScheduleRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Setup the list of schedules in the repository
    ///
    /// # Parameters
    ///
    /// * `schedules` - The list of schedules to setup
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn setup(&mut self, schedules: &[&'static str]) -> Result<(), Self::Error>;

    /// List the schedules in the repository, with the last time they were run
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails.
    async fn list(&mut self) -> Result<Vec<ScheduleStatus>, Self::Error>;
}

repository_impl!(QueueScheduleRepository:
    async fn setup(
        &mut self,
        schedules: &[&'static str],
    ) -> Result<(), Self::Error>;

    async fn list(&mut self) -> Result<Vec<ScheduleStatus>, Self::Error>;
);
