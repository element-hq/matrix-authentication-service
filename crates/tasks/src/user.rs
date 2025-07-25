// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context;
use async_trait::async_trait;
use mas_storage::{
    RepositoryAccess,
    compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter,
    queue::{DeactivateUserJob, ReactivateUserJob},
    user::{BrowserSessionFilter, UserEmailFilter, UserRepository},
};
use tracing::info;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

/// Job to deactivate a user, both locally and on the Matrix homeserver.
#[async_trait]
impl RunnableJob for DeactivateUserJob {
    #[tracing::instrument(
    name = "job.deactivate_user"
        fields(user.id = %self.user_id(), erase = %self.hs_erase()),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let matrix = state.matrix_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let user = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("User not found")
            .map_err(JobError::fail)?;

        // Let's first deactivate the user
        let user = repo
            .user()
            .deactivate(clock, user)
            .await
            .context("Failed to deactivate user")
            .map_err(JobError::retry)?;

        // Kill all sessions for the user
        let n = repo
            .browser_session()
            .finish_bulk(
                clock,
                BrowserSessionFilter::new().for_user(&user).active_only(),
            )
            .await
            .map_err(JobError::retry)?;
        info!(affected = n, "Killed all browser sessions for user");

        let n = repo
            .oauth2_session()
            .finish_bulk(
                clock,
                OAuth2SessionFilter::new().for_user(&user).active_only(),
            )
            .await
            .map_err(JobError::retry)?;
        info!(affected = n, "Killed all OAuth 2.0 sessions for user");

        let n = repo
            .compat_session()
            .finish_bulk(
                clock,
                CompatSessionFilter::new().for_user(&user).active_only(),
            )
            .await
            .map_err(JobError::retry)?;
        info!(affected = n, "Killed all compatibility sessions for user");

        // Delete all the email addresses for the user
        let n = repo
            .user_email()
            .remove_bulk(UserEmailFilter::new().for_user(&user))
            .await
            .map_err(JobError::retry)?;
        info!(affected = n, "Removed all email addresses for user");

        // Before calling back to the homeserver, commit the changes to the database, as
        // we want the user to be locked out as soon as possible
        repo.save().await.map_err(JobError::retry)?;

        info!("Deactivating user {} on homeserver", user.username);
        matrix
            .delete_user(&user.username, self.hs_erase())
            .await
            .map_err(JobError::retry)?;

        Ok(())
    }
}

/// Job to reactivate a user, both locally and on the Matrix homeserver.
#[async_trait]
impl RunnableJob for ReactivateUserJob {
    #[tracing::instrument(
        name = "job.reactivate_user",
        fields(user.id = %self.user_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let matrix = state.matrix_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let user = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("User not found")
            .map_err(JobError::fail)?;

        info!("Reactivating user {} on homeserver", user.username);
        matrix
            .reactivate_user(&user.username)
            .await
            .map_err(JobError::retry)?;

        // We want to reactivate the user from our side only once it has been
        // reactivated on the homeserver
        let _user = repo
            .user()
            .reactivate(user)
            .await
            .map_err(JobError::retry)?;
        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}
