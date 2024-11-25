// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Database-related tasks

use async_trait::async_trait;
use mas_storage::queue::CleanupExpiredTokensJob;
use tracing::{debug, info};

use crate::{
    new_queue::{JobContext, JobError, RunnableJob},
    State,
};

#[async_trait]
impl RunnableJob for CleanupExpiredTokensJob {
    #[tracing::instrument(name = "job.cleanup_expired_tokens", skip_all, err)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let count = repo
            .oauth2_access_token()
            .cleanup_expired(&clock)
            .await
            .map_err(JobError::retry)?;
        repo.save().await.map_err(JobError::retry)?;

        if count == 0 {
            debug!("no token to clean up");
        } else {
            info!(count, "cleaned up expired tokens");
        }

        Ok(())
    }
}
