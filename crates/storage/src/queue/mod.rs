// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! A module containing repositories for the job queue

mod job;
mod schedule;
mod tasks;
mod worker;

pub use self::{
    job::{InsertableJob, Job, JobMetadata, QueueJobRepository, QueueJobRepositoryExt},
    schedule::{QueueScheduleRepository, ScheduleStatus},
    tasks::*,
    worker::{QueueWorkerRepository, Worker},
};
