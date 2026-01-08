// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Database-related tasks

use std::time::Duration;

use async_trait::async_trait;
use mas_storage::queue::{CleanupExpiredTokensJob, PruneStalePolicyDataJob};
use tracing::{debug, info};

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

const BATCH_SIZE: usize = 1000;

#[async_trait]
impl RunnableJob for CleanupExpiredTokensJob {
    #[tracing::instrument(name = "job.cleanup_expired_tokens", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Cleanup tokens that were revoked more than an hour ago
        let until = state.clock.now() - chrono::Duration::hours(1);
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            // This returns the number of deleted tokens, and the last revoked_at timestamp
            let (count, last_revoked_at) = repo
                .oauth2_access_token()
                .cleanup_revoked(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_revoked_at;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_COUNT,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no token to clean up");
        } else {
            info!(count = total, "cleaned up revoked tokens");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(60))
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
