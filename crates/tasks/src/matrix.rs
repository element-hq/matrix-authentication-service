// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::collections::HashSet;

use anyhow::Context;
use async_trait::async_trait;
use mas_data_model::Device;
use mas_matrix::ProvisionRequest;
use mas_storage::{
    compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter,
    queue::{
        DeleteDeviceJob, ProvisionDeviceJob, ProvisionUserJob, QueueJobRepositoryExt as _,
        SyncDevicesJob,
    },
    user::{UserEmailRepository, UserRepository},
    Pagination, RepositoryAccess,
};
use tracing::info;

use crate::{
    new_queue::{JobContext, RunnableJob},
    State,
};

/// Job to provision a user on the Matrix homeserver.
/// This works by doing a PUT request to the
/// /_synapse/admin/v2/users/{user_id} endpoint.
#[async_trait]
impl RunnableJob for ProvisionUserJob {
    #[tracing::instrument(
        name = "job.provision_user"
        fields(user.id = %self.user_id()),
        skip_all,
        err(Debug),
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), anyhow::Error> {
        let matrix = state.matrix_connection();
        let mut repo = state.repository().await?;
        let mut rng = state.rng();
        let clock = state.clock();

        let user = repo
            .user()
            .lookup(self.user_id())
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

        if let Some(display_name) = self.display_name_to_set() {
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
        repo.queue_job()
            .schedule_job(&mut rng, &clock, sync_device_job)
            .await?;

        repo.save().await?;

        Ok(())
    }
}

/// Job to provision a device on the Matrix homeserver.
///
/// This job is deprecated and therefore just schedules a [`SyncDevicesJob`]
#[async_trait]
impl RunnableJob for ProvisionDeviceJob {
    #[tracing::instrument(
        name = "job.provision_device"
        fields(
            user.id = %self.user_id(),
            device.id = %self.device_id(),
        ),
        skip_all,
        err(Debug),
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), anyhow::Error> {
        let mut repo = state.repository().await?;
        let mut rng = state.rng();
        let clock = state.clock();

        let user = repo
            .user()
            .lookup(self.user_id())
            .await?
            .context("User not found")?;

        // Schedule a device sync job
        repo.queue_job()
            .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
            .await?;

        Ok(())
    }
}

/// Job to delete a device from a user's account.
///
/// This job is deprecated and therefore just schedules a [`SyncDevicesJob`]
#[async_trait]
impl RunnableJob for DeleteDeviceJob {
    #[tracing::instrument(
        name = "job.delete_device"
        fields(
            user.id = %self.user_id(),
            device.id = %self.device_id(),
        ),
        skip_all,
        err(Debug),
    )]
    #[tracing::instrument(
        name = "job.delete_device"
        fields(
            user.id = %self.user_id(),
            device.id = %self.device_id(),
        ),
        skip_all,
        err(Debug),
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), anyhow::Error> {
        let mut rng = state.rng();
        let clock = state.clock();
        let mut repo = state.repository().await?;

        let user = repo
            .user()
            .lookup(self.user_id())
            .await?
            .context("User not found")?;

        // Schedule a device sync job
        repo.queue_job()
            .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
            .await?;

        Ok(())
    }
}

/// Job to sync the list of devices of a user with the homeserver.
#[async_trait]
impl RunnableJob for SyncDevicesJob {
    #[tracing::instrument(
        name = "job.sync_devices",
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
}
