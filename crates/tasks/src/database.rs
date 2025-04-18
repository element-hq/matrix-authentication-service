// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Database-related tasks

use async_trait::async_trait;
use mas_storage::queue::{CleanupExpiredTokensJob, PruneStalePolicyDataJob};
use tracing::{debug, info};

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupExpiredTokensJob {
    #[tracing::instrument(name = "job.cleanup_expired_tokens", skip_all)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let count = repo
            .oauth2_access_token()
            .cleanup_revoked(&clock)
            .await
            .map_err(JobError::retry)?;
        repo.save().await.map_err(JobError::retry)?;

        if count == 0 {
            debug!("no token to clean up");
        } else {
            info!(count, "cleaned up revoked tokens");
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
