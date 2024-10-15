// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context;
use apalis_core::{context::JobContext, executor::TokioExecutor, monitor::Monitor};
use mas_storage::{
    compat::CompatSessionFilter,
    job::JobWithSpanContext,
    oauth2::OAuth2SessionFilter,
    queue::{DeactivateUserJob, ReactivateUserJob},
    user::{BrowserSessionFilter, UserRepository},
    RepositoryAccess,
};
use tracing::info;

use crate::{storage::PostgresStorageFactory, JobContextExt, State};

/// Job to deactivate a user, both locally and on the Matrix homeserver.
#[tracing::instrument(
    name = "job.deactivate_user"
    fields(user.id = %job.user_id(), erase = %job.hs_erase()),
    skip_all,
    err(Debug),
)]
async fn deactivate_user(
    job: JobWithSpanContext<DeactivateUserJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let clock = state.clock();
    let matrix = state.matrix_connection();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
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
    matrix.delete_user(&mxid, job.hs_erase()).await?;

    Ok(())
}

/// Job to reactivate a user, both locally and on the Matrix homeserver.
#[tracing::instrument(
    name = "job.reactivate_user",
    fields(user.id = %job.user_id()),
    skip_all,
    err(Debug),
)]
pub async fn reactivate_user(
    job: JobWithSpanContext<ReactivateUserJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let matrix = state.matrix_connection();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
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

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
    storage_factory: &PostgresStorageFactory,
) -> Monitor<TokioExecutor> {
    let deactivate_user_worker =
        crate::build!(DeactivateUserJob => deactivate_user, suffix, state, storage_factory);

    let reactivate_user_worker =
        crate::build!(ReactivateUserJob => reactivate_user, suffix, state, storage_factory);

    monitor
        .register(deactivate_user_worker)
        .register(reactivate_user_worker)
}
