// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Session cleanup tasks

use std::time::Duration;

use async_trait::async_trait;
use mas_storage::queue::{
    CleanupFinishedCompatSessionsJob, CleanupFinishedOAuth2SessionsJob,
    CleanupFinishedUserSessionsJob, CleanupInactiveCompatSessionIpsJob,
    CleanupInactiveOAuth2SessionIpsJob, CleanupInactiveUserSessionIpsJob,
};
use tracing::{debug, info};

use super::BATCH_SIZE;
use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupFinishedCompatSessionsJob {
    #[tracing::instrument(name = "job.cleanup_finished_compat_sessions", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Cleanup compat sessions that were finished more than 30 days ago
        let until = state.clock.now() - chrono::Duration::days(30);
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            // This returns the number of deleted sessions, and the last finished_at
            // timestamp
            let (count, last_finished_at) = repo
                .compat_session()
                .cleanup_finished(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_finished_at;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_SIZE,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no finished compat sessions to clean up");
        } else {
            info!(count = total, "cleaned up finished compat sessions");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupFinishedOAuth2SessionsJob {
    #[tracing::instrument(name = "job.cleanup_finished_oauth2_sessions", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Cleanup OAuth2 sessions that were finished more than 30 days ago
        let until = state.clock.now() - chrono::Duration::days(30);
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            // This returns the number of deleted sessions, and the last finished_at
            // timestamp
            let (count, last_finished_at) = repo
                .oauth2_session()
                .cleanup_finished(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_finished_at;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_SIZE,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no finished OAuth2 sessions to clean up");
        } else {
            info!(count = total, "cleaned up finished OAuth2 sessions");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupFinishedUserSessionsJob {
    #[tracing::instrument(name = "job.cleanup_finished_user_sessions", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Cleanup user/browser sessions that were finished more than 30 days ago
        let until = state.clock.now() - chrono::Duration::days(30);
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            // This returns the number of deleted sessions, and the last finished_at
            // timestamp. Only deletes sessions that have no child sessions
            // (compat_sessions or oauth2_sessions).
            let (count, last_finished_at) = repo
                .browser_session()
                .cleanup_finished(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_finished_at;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_SIZE,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no finished user sessions to clean up");
        } else {
            info!(count = total, "cleaned up finished user sessions");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupInactiveOAuth2SessionIpsJob {
    #[tracing::instrument(name = "job.cleanup_inactive_oauth2_session_ips", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Clear IPs from sessions inactive for 30+ days
        let threshold = state.clock.now() - chrono::Duration::days(30);
        let mut total = 0;

        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (count, last_active_at) = repo
                .oauth2_session()
                .cleanup_inactive_ips(since, threshold, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_active_at;
            total += count;

            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no OAuth2 session IPs to clean up");
        } else {
            info!(count = total, "cleaned up inactive OAuth2 session IPs");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupInactiveCompatSessionIpsJob {
    #[tracing::instrument(name = "job.cleanup_inactive_compat_session_ips", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Clear IPs from sessions inactive for 30+ days
        let threshold = state.clock.now() - chrono::Duration::days(30);
        let mut total = 0;

        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (count, last_active_at) = repo
                .compat_session()
                .cleanup_inactive_ips(since, threshold, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_active_at;
            total += count;

            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no compat session IPs to clean up");
        } else {
            info!(count = total, "cleaned up inactive compat session IPs");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupInactiveUserSessionIpsJob {
    #[tracing::instrument(name = "job.cleanup_inactive_user_session_ips", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Clear IPs from sessions inactive for 30+ days
        let threshold = state.clock.now() - chrono::Duration::days(30);
        let mut total = 0;

        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (count, last_active_at) = repo
                .browser_session()
                .cleanup_inactive_ips(since, threshold, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_active_at;
            total += count;

            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no user session IPs to clean up");
        } else {
            info!(count = total, "cleaned up inactive user session IPs");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}
