// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! OAuth grants and upstream OAuth cleanup tasks

use std::time::Duration;

use async_trait::async_trait;
use mas_storage::queue::{
    CleanupOAuthAuthorizationGrantsJob, CleanupOAuthDeviceCodeGrantsJob,
    CleanupUpstreamOAuthLinksJob, CleanupUpstreamOAuthSessionsJob,
};
use tracing::{debug, info};
use ulid::Ulid;

use super::BATCH_SIZE;
use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupOAuthAuthorizationGrantsJob {
    #[tracing::instrument(name = "job.cleanup_oauth_authorization_grants", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Remove authorization grants after 7 days. They are in practice only
        // valid for a short time, but keeping them around helps investigate abuse
        // patterns.
        let until = state.clock.now() - chrono::Duration::days(7);
        // We use the fact that ULIDs include the creation time in their first 48 bits
        // as a cursor
        let until = Ulid::from_parts(
            u64::try_from(until.timestamp_millis()).unwrap_or(u64::MIN),
            u128::MAX,
        );
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;
            // This returns the number of deleted grants, and the greatest ULID processed
            let (count, cursor) = repo
                .oauth2_authorization_grant()
                .cleanup(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;
            since = cursor;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_SIZE,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no authorization grants to clean up");
        } else {
            info!(count = total, "cleaned up authorization grants");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupOAuthDeviceCodeGrantsJob {
    #[tracing::instrument(name = "job.cleanup_oauth_device_code_grants", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Remove device code grants after 7 days. They are in practice only
        // valid for a short time, but keeping them around helps investigate abuse
        // patterns.
        let until = state.clock.now() - chrono::Duration::days(7);
        // We use the fact that ULIDs include the creation time in their first 48 bits
        // as a cursor
        let until = Ulid::from_parts(
            u64::try_from(until.timestamp_millis()).unwrap_or(u64::MIN),
            u128::MAX,
        );
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;
            // This returns the number of deleted grants, and the greatest ULID processed
            let (count, cursor) = repo
                .oauth2_device_code_grant()
                .cleanup(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;
            since = cursor;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_SIZE,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no device code grants to clean up");
        } else {
            info!(count = total, "cleaned up device code grants");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupUpstreamOAuthSessionsJob {
    #[tracing::instrument(name = "job.cleanup_upstream_oauth_sessions", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Remove pending upstream OAuth authorization sessions after 7 days.
        let until = state.clock.now() - chrono::Duration::days(7);
        let until = Ulid::from_parts(
            u64::try_from(until.timestamp_millis()).unwrap_or(u64::MIN),
            u128::MAX,
        );
        let mut total = 0;

        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;
            let (count, cursor) = repo
                .upstream_oauth_session()
                .cleanup_orphaned(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;
            since = cursor;
            total += count;

            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no pending upstream OAuth sessions to clean up");
        } else {
            info!(count = total, "cleaned up pending upstream OAuth sessions");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupUpstreamOAuthLinksJob {
    #[tracing::instrument(name = "job.cleanup_upstream_oauth_links", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Remove orphaned upstream OAuth links after 7 days.
        let until = state.clock.now() - chrono::Duration::days(7);
        let until = Ulid::from_parts(
            u64::try_from(until.timestamp_millis()).unwrap_or(u64::MIN),
            u128::MAX,
        );
        let mut total = 0;

        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;
            let (count, cursor) = repo
                .upstream_oauth_link()
                .cleanup_orphaned(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;
            since = cursor;
            total += count;

            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no orphaned upstream OAuth links to clean up");
        } else {
            info!(count = total, "cleaned up orphaned upstream OAuth links");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}
