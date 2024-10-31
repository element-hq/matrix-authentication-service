// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context;
use async_trait::async_trait;
use mas_storage::{
    compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter,
    queue::{DeactivateUserJob, ReactivateUserJob},
    user::{BrowserSessionFilter, UserRepository},
    RepositoryAccess,
};
use tracing::info;

use crate::{
    new_queue::{JobContext, RunnableJob},
    State,
};

/// Job to deactivate a user, both locally and on the Matrix homeserver.
#[async_trait]
impl RunnableJob for DeactivateUserJob {
    #[tracing::instrument(
    name = "job.deactivate_user"
        fields(user.id = %self.user_id(), erase = %self.hs_erase()),
        skip_all,
        err(Debug),
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), anyhow::Error> {
        let clock = state.clock();
        let matrix = state.matrix_connection();
        let mut repo = state.repository().await?;

        let user = repo
            .user()
            .lookup(self.user_id())
            .await?
            .context("User not found")?;

        // Let's first lock the user
        let user = repo
            .user()
            .lock(&clock, user)
            .await
            .context("Failed to lock user")?;

        // Kill all sessions for the user
        let n = repo
            .browser_session()
            .finish_bulk(
                &clock,
                BrowserSessionFilter::new().for_user(&user).active_only(),
            )
            .await?;
        info!(affected = n, "Killed all browser sessions for user");

        let n = repo
            .oauth2_session()
            .finish_bulk(
                &clock,
                OAuth2SessionFilter::new().for_user(&user).active_only(),
            )
            .await?;
        info!(affected = n, "Killed all OAuth 2.0 sessions for user");

        let n = repo
            .compat_session()
            .finish_bulk(
                &clock,
                CompatSessionFilter::new().for_user(&user).active_only(),
            )
            .await?;
        info!(affected = n, "Killed all compatibility sessions for user");

        // Before calling back to the homeserver, commit the changes to the database, as
        // we want the user to be locked out as soon as possible
        repo.save().await?;

        let mxid = matrix.mxid(&user.username);
        info!("Deactivating user {} on homeserver", mxid);
        matrix.delete_user(&mxid, self.hs_erase()).await?;

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
        err(Debug),
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), anyhow::Error> {
        let matrix = state.matrix_connection();
        let mut repo = state.repository().await?;

        let user = repo
            .user()
            .lookup(self.user_id())
            .await?
            .context("User not found")?;

        let mxid = matrix.mxid(&user.username);
        info!("Reactivating user {} on homeserver", mxid);
        matrix.reactivate_user(&mxid).await?;

        // We want to unlock the user from our side only once it has been reactivated on
        // the homeserver
        let _user = repo.user().unlock(user).await?;
        repo.save().await?;

        Ok(())
    }
}
