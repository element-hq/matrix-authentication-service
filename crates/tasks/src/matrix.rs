// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::collections::HashSet;

use anyhow::Context;
use apalis_core::{context::JobContext, executor::TokioExecutor, monitor::Monitor};
use mas_data_model::Device;
use mas_matrix::ProvisionRequest;
use mas_storage::{
    compat::CompatSessionFilter,
    job::{JobRepositoryExt as _, JobWithSpanContext},
    oauth2::OAuth2SessionFilter,
    queue::{DeleteDeviceJob, ProvisionDeviceJob, ProvisionUserJob, SyncDevicesJob},
    user::{UserEmailRepository, UserRepository},
    Pagination, RepositoryAccess,
};
use tracing::info;

use crate::{storage::PostgresStorageFactory, JobContextExt, State};

/// Job to provision a user on the Matrix homeserver.
/// This works by doing a PUT request to the /_synapse/admin/v2/users/{user_id}
/// endpoint.
#[tracing::instrument(
    name = "job.provision_user"
    fields(user.id = %job.user_id()),
    skip_all,
    err(Debug),
)]
async fn provision_user(
    job: JobWithSpanContext<ProvisionUserJob>,
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
    let emails = repo
        .user_email()
        .all(&user)
        .await?
        .into_iter()
        .filter(|email| email.confirmed_at.is_some())
        .map(|email| email.email)
        .collect();
    let mut request = ProvisionRequest::new(mxid.clone(), user.sub.clone()).set_emails(emails);

    if let Some(display_name) = job.display_name_to_set() {
        request = request.set_displayname(display_name.to_owned());
    }

    let created = matrix.provision_user(&request).await?;

    if created {
        info!(%user.id, %mxid, "User created");
    } else {
        info!(%user.id, %mxid, "User updated");
    }

    // Schedule a device sync job
    let sync_device_job = SyncDevicesJob::new(&user);
    repo.job().schedule_job(sync_device_job).await?;

    repo.save().await?;

    Ok(())
}

/// Job to provision a device on the Matrix homeserver.
///
/// This job is deprecated and therefore just schedules a [`SyncDevicesJob`]
#[tracing::instrument(
    name = "job.provision_device"
    fields(
        user.id = %job.user_id(),
        device.id = %job.device_id(),
    ),
    skip_all,
    err(Debug),
)]
async fn provision_device(
    job: JobWithSpanContext<ProvisionDeviceJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    // Schedule a device sync job
    repo.job().schedule_job(SyncDevicesJob::new(&user)).await?;

    Ok(())
}

/// Job to delete a device from a user's account.
///
/// This job is deprecated and therefore just schedules a [`SyncDevicesJob`]
#[tracing::instrument(
    name = "job.delete_device"
    fields(
        user.id = %job.user_id(),
        device.id = %job.device_id(),
    ),
    skip_all,
    err(Debug),
)]
async fn delete_device(
    job: JobWithSpanContext<DeleteDeviceJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let mut repo = state.repository().await?;

    let user = repo
        .user()
        .lookup(job.user_id())
        .await?
        .context("User not found")?;

    // Schedule a device sync job
    repo.job().schedule_job(SyncDevicesJob::new(&user)).await?;

    Ok(())
}

/// Job to sync the list of devices of a user with the homeserver.
#[tracing::instrument(
    name = "job.sync_devices",
    fields(user.id = %job.user_id()),
    skip_all,
    err(Debug),
)]
async fn sync_devices(
    job: JobWithSpanContext<SyncDevicesJob>,
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

    // Lock the user sync to make sure we don't get into a race condition
    repo.user().acquire_lock_for_sync(&user).await?;

    let mut devices = HashSet::new();

    // Cycle through all the compat sessions of the user, and grab the devices
    let mut cursor = Pagination::first(100);
    loop {
        let page = repo
            .compat_session()
            .list(
                CompatSessionFilter::new().for_user(&user).active_only(),
                cursor,
            )
            .await?;

        for (compat_session, _) in page.edges {
            devices.insert(compat_session.device.as_str().to_owned());
            cursor = cursor.after(compat_session.id);
        }

        if !page.has_next_page {
            break;
        }
    }

    // Cycle though all the oauth2 sessions of the user, and grab the devices
    let mut cursor = Pagination::first(100);
    loop {
        let page = repo
            .oauth2_session()
            .list(
                OAuth2SessionFilter::new().for_user(&user).active_only(),
                cursor,
            )
            .await?;

        for oauth2_session in page.edges {
            for scope in &*oauth2_session.scope {
                if let Some(device) = Device::from_scope_token(scope) {
                    devices.insert(device.as_str().to_owned());
                }
            }

            cursor = cursor.after(oauth2_session.id);
        }

        if !page.has_next_page {
            break;
        }
    }

    let mxid = matrix.mxid(&user.username);
    matrix.sync_devices(&mxid, devices).await?;

    // We kept the connection until now, so that we still hold the lock on the user
    // throughout the sync
    repo.save().await?;

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
    storage_factory: &PostgresStorageFactory,
) -> Monitor<TokioExecutor> {
    let provision_user_worker =
        crate::build!(ProvisionUserJob => provision_user, suffix, state, storage_factory);
    let provision_device_worker =
        crate::build!(ProvisionDeviceJob => provision_device, suffix, state, storage_factory);
    let delete_device_worker =
        crate::build!(DeleteDeviceJob => delete_device, suffix, state, storage_factory);
    let sync_devices_worker =
        crate::build!(SyncDevicesJob => sync_devices, suffix, state, storage_factory);

    monitor
        .register(provision_user_worker)
        .register(provision_device_worker)
        .register(delete_device_worker)
        .register(sync_devices_worker)
}
