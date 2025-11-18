// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashSet;

use anyhow::Context;
use async_trait::async_trait;
use mas_data_model::Device;
use mas_matrix::ProvisionRequest;
use mas_storage::{
    Pagination, RepositoryAccess,
    compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter,
    personal::PersonalSessionFilter,
    queue::{
        DeleteDeviceJob, ProvisionDeviceJob, ProvisionUserJob, QueueJobRepositoryExt as _,
        SyncDevicesJob,
    },
    user::{UserEmailRepository, UserRepository},
};
use tracing::info;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

/// Job to provision a user on the Matrix homeserver.
/// This works by doing a PUT request to the
/// `/_synapse/admin/v2/users/{user_id}` endpoint.
#[async_trait]
impl RunnableJob for ProvisionUserJob {
    #[tracing::instrument(
        name = "job.provision_user"
        fields(user.id = %self.user_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let matrix = state.matrix_connection();
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let mut rng = state.rng();
        let clock = state.clock();

        let user = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("User not found")
            .map_err(JobError::fail)?;

        let emails = repo
            .user_email()
            .all(&user)
            .await
            .map_err(JobError::retry)?
            .into_iter()
            .map(|email| email.email)
            .collect();
        let mut request =
            ProvisionRequest::new(user.username.clone(), user.sub.clone()).set_emails(emails);

        if let Some(display_name) = self.display_name_to_set() {
            request = request.set_displayname(display_name.to_owned());
        }

        let created = matrix
            .provision_user(&request)
            .await
            .map_err(JobError::retry)?;

        let mxid = matrix.mxid(&user.username);
        if created {
            info!(%user.id, %mxid, "User created");
        } else {
            info!(%user.id, %mxid, "User updated");
        }

        // Schedule a device sync job
        let sync_device_job = SyncDevicesJob::new(&user);
        repo.queue_job()
            .schedule_job(&mut rng, clock, sync_device_job)
            .await
            .map_err(JobError::retry)?;

        repo.save().await.map_err(JobError::retry)?;

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
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let mut rng = state.rng();
        let clock = state.clock();

        let user = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("User not found")
            .map_err(JobError::fail)?;

        // Schedule a device sync job
        repo.queue_job()
            .schedule_job(&mut rng, clock, SyncDevicesJob::new(&user))
            .await
            .map_err(JobError::retry)?;

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
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut rng = state.rng();
        let clock = state.clock();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let user = repo
            .user()
            .lookup(self.user_id())
            .await
            .map_err(JobError::retry)?
            .context("User not found")
            .map_err(JobError::fail)?;

        // Schedule a device sync job
        repo.queue_job()
            .schedule_job(&mut rng, clock, SyncDevicesJob::new(&user))
            .await
            .map_err(JobError::retry)?;

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

        // Lock the user sync to make sure we don't get into a race condition
        repo.user()
            .acquire_lock_for_sync(&user)
            .await
            .map_err(JobError::retry)?;

        let mut devices = HashSet::new();

        // Cycle through all the compat sessions of the user, and grab the devices
        let mut cursor = Pagination::first(5000);
        loop {
            let page = repo
                .compat_session()
                .list(
                    CompatSessionFilter::new().for_user(&user).active_only(),
                    cursor,
                )
                .await
                .map_err(JobError::retry)?;

            for edge in page.edges {
                let (compat_session, _) = edge.node;
                if let Some(ref device) = compat_session.device {
                    devices.insert(device.as_str().to_owned());
                }
                cursor = cursor.after(edge.cursor);
            }

            if !page.has_next_page {
                break;
            }
        }

        // Cycle though all the oauth2 sessions of the user, and grab the devices
        let mut cursor = Pagination::first(5000);
        loop {
            let page = repo
                .oauth2_session()
                .list(
                    OAuth2SessionFilter::new().for_user(&user).active_only(),
                    cursor,
                )
                .await
                .map_err(JobError::retry)?;

            for edge in page.edges {
                for scope in &*edge.node.scope {
                    if let Some(device) = Device::from_scope_token(scope) {
                        devices.insert(device.as_str().to_owned());
                    }
                }

                cursor = cursor.after(edge.cursor);
            }

            if !page.has_next_page {
                break;
            }
        }

        // Cycle through all the personal sessions of the user and get the devices
        let mut cursor = Pagination::first(5000);
        loop {
            let page = repo
                .personal_session()
                .list(
                    PersonalSessionFilter::new()
                        .for_actor_user(&user)
                        .active_only(),
                    cursor,
                )
                .await
                .map_err(JobError::retry)?;

            for edge in page.edges {
                let (session, _) = &edge.node;
                for scope in &*session.scope {
                    if let Some(device) = Device::from_scope_token(scope) {
                        devices.insert(device.as_str().to_owned());
                    }
                }

                cursor = cursor.after(edge.cursor);
            }

            if !page.has_next_page {
                break;
            }
        }

        matrix
            .sync_devices(&user.username, devices)
            .await
            .map_err(JobError::retry)?;

        // We kept the connection until now, so that we still hold the lock on the user
        // throughout the sync
        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}
