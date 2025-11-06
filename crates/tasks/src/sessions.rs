// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashSet;

use async_trait::async_trait;
use chrono::Duration;
use mas_storage::{
    compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter,
    queue::{
        ExpireInactiveCompatSessionsJob, ExpireInactiveOAuthSessionsJob, ExpireInactiveSessionsJob,
        ExpireInactiveUserSessionsJob, QueueJobRepositoryExt, SyncDevicesJob,
    },
    user::BrowserSessionFilter,
};

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for ExpireInactiveSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let Some(config) = state.site_config().session_expiration.as_ref() else {
            // Automatic session expiration is disabled
            return Ok(());
        };

        let clock = state.clock();
        let mut rng = state.rng();
        let now = clock.now();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        if let Some(ttl) = config.oauth_session_inactivity_ttl {
            repo.queue_job()
                .schedule_job(
                    &mut rng,
                    clock,
                    ExpireInactiveOAuthSessionsJob::new(now - ttl),
                )
                .await
                .map_err(JobError::retry)?;
        }

        if let Some(ttl) = config.compat_session_inactivity_ttl {
            repo.queue_job()
                .schedule_job(
                    &mut rng,
                    clock,
                    ExpireInactiveCompatSessionsJob::new(now - ttl),
                )
                .await
                .map_err(JobError::retry)?;
        }

        if let Some(ttl) = config.user_session_inactivity_ttl {
            repo.queue_job()
                .schedule_job(
                    &mut rng,
                    clock,
                    ExpireInactiveUserSessionsJob::new(now - ttl),
                )
                .await
                .map_err(JobError::retry)?;
        }

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}

#[async_trait]
impl RunnableJob for ExpireInactiveOAuthSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let clock = state.clock();
        let mut rng = state.rng();
        let mut users_synced = HashSet::new();

        // This delay is used to space out the device sync jobs
        // We add 10 seconds between each device sync, meaning that it will spread out
        // the syncs over ~16 minutes max if we get a full batch of 100 users
        let mut delay = Duration::minutes(1);

        let filter = OAuth2SessionFilter::new()
            .with_last_active_before(self.threshold())
            .for_any_user()
            .only_dynamic_clients()
            .active_only();

        let pagination = self.pagination(100);

        let page = repo
            .oauth2_session()
            .list(filter, pagination)
            .await
            .map_err(JobError::retry)?;

        if let Some(job) = self.next(&page) {
            tracing::info!("Scheduling job to expire the next batch of inactive sessions");
            repo.queue_job()
                .schedule_job(&mut rng, clock, job)
                .await
                .map_err(JobError::retry)?;
        }

        for edge in page.edges {
            if let Some(user_id) = edge.node.user_id {
                let inserted = users_synced.insert(user_id);
                if inserted {
                    tracing::info!(user.id = %user_id, "Scheduling devices sync for user");
                    repo.queue_job()
                        .schedule_job_later(
                            &mut rng,
                            clock,
                            SyncDevicesJob::new_for_id(user_id),
                            clock.now() + delay,
                        )
                        .await
                        .map_err(JobError::retry)?;
                    delay += Duration::seconds(10);
                }
            }

            repo.oauth2_session()
                .finish(clock, edge.node)
                .await
                .map_err(JobError::retry)?;
        }

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}

#[async_trait]
impl RunnableJob for ExpireInactiveCompatSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let clock = state.clock();
        let mut rng = state.rng();
        let mut users_synced = HashSet::new();

        // This delay is used to space out the device sync jobs
        // We add 10 seconds between each device sync, meaning that it will spread out
        // the syncs over ~16 minutes max if we get a full batch of 100 users
        let mut delay = Duration::minutes(1);

        let filter = CompatSessionFilter::new()
            .with_last_active_before(self.threshold())
            .active_only();

        let pagination = self.pagination(100);

        let page = repo
            .compat_session()
            .list(filter, pagination)
            .await
            .map_err(JobError::retry)?
            .map(|(c, _)| c);

        if let Some(job) = self.next(&page) {
            tracing::info!("Scheduling job to expire the next batch of inactive sessions");
            repo.queue_job()
                .schedule_job(&mut rng, clock, job)
                .await
                .map_err(JobError::retry)?;
        }

        for edge in page.edges {
            let inserted = users_synced.insert(edge.node.user_id);
            if inserted {
                tracing::info!(user.id = %edge.node.user_id, "Scheduling devices sync for user");
                repo.queue_job()
                    .schedule_job_later(
                        &mut rng,
                        clock,
                        SyncDevicesJob::new_for_id(edge.node.user_id),
                        clock.now() + delay,
                    )
                    .await
                    .map_err(JobError::retry)?;
                delay += Duration::seconds(10);
            }

            repo.compat_session()
                .finish(clock, edge.node)
                .await
                .map_err(JobError::retry)?;
        }

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}

#[async_trait]
impl RunnableJob for ExpireInactiveUserSessionsJob {
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let clock = state.clock();
        let mut rng = state.rng();

        let filter = BrowserSessionFilter::new()
            .with_last_active_before(self.threshold())
            .active_only();

        let pagination = self.pagination(100);

        let page = repo
            .browser_session()
            .list(filter, pagination)
            .await
            .map_err(JobError::retry)?;

        if let Some(job) = self.next(&page) {
            tracing::info!("Scheduling job to expire the next batch of inactive sessions");
            repo.queue_job()
                .schedule_job(&mut rng, clock, job)
                .await
                .map_err(JobError::retry)?;
        }

        for edge in page.edges {
            repo.browser_session()
                .finish(clock, edge.node)
                .await
                .map_err(JobError::retry)?;
        }

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}
