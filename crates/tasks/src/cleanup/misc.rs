// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Miscellaneous cleanup tasks

use std::time::Duration;

use async_trait::async_trait;
use mas_storage::queue::{
    CleanupOldPasskeyChallengesJob, CleanupQueueJobsJob, PruneStalePolicyDataJob,
};
use tracing::{debug, info};
use ulid::Ulid;

use super::BATCH_SIZE;
use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupQueueJobsJob {
    #[tracing::instrument(name = "job.cleanup_queue_jobs", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Remove completed and failed queue jobs after 30 days.
        // Keep them for debugging purposes.
        let until = state.clock.now() - chrono::Duration::days(30);
        let until = Ulid::from_parts(
            u64::try_from(until.timestamp_millis()).unwrap_or(u64::MIN),
            u128::MAX,
        );
        let mut total = 0;

        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;
            let (count, cursor) = repo
                .queue_job()
                .cleanup(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;
            since = cursor;
            total += count;

            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no queue jobs to clean up");
        } else {
            info!(count = total, "cleaned up queue jobs");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupOldPasskeyChallengesJob {
    #[tracing::instrument(name = "job.cleanup_old_passkey_challenges", skip_all)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let count = repo
            .user_passkey()
            .cleanup_challenges(clock)
            .await
            .map_err(JobError::retry)?;
        repo.save().await.map_err(JobError::retry)?;

        if count == 0 {
            debug!("no passkey challenges to clean up");
        } else {
            info!(count, "cleaned up old passkey challenges");
        }

        Ok(())
    }
}

#[async_trait]
impl RunnableJob for PruneStalePolicyDataJob {
    #[tracing::instrument(name = "job.prune_stale_policy_data", skip_all)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        // Keep the last 10 policy data
        let count = repo
            .policy_data()
            .prune(10)
            .await
            .map_err(JobError::retry)?;

        repo.save().await.map_err(JobError::retry)?;

        if count == 0 {
            debug!("no stale policy data to prune");
        } else {
            info!(count, "pruned stale policy data");
        }

        Ok(())
    }
}
