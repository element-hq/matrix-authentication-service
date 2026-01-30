// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! User-related cleanup tasks

use std::time::Duration;

use async_trait::async_trait;
use mas_storage::queue::{
    CleanupUserEmailAuthenticationsJob, CleanupUserRecoverySessionsJob, CleanupUserRegistrationsJob,
};
use tracing::{debug, info};
use ulid::Ulid;

use super::BATCH_SIZE;
use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for CleanupUserRegistrationsJob {
    #[tracing::instrument(name = "job.cleanup_user_registrations", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Remove user registrations after 30 days. They are in practice only
        // valid for 1h, but keeping them around helps investigate abuse patterns.
        let until = state.clock.now() - chrono::Duration::days(30);
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
            // This returns the number of deleted registrations, and the greatest ULID
            // processed
            let (count, cursor) = repo
                .user_registration()
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
            debug!("no user registrations to clean up");
        } else {
            info!(count = total, "cleaned up user registrations");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupUserRecoverySessionsJob {
    #[tracing::instrument(name = "job.cleanup_user_recovery_sessions", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Remove recovery sessions after 7 days. They are in practice only
        // valid for a short time (tickets expire after 10 minutes), but keeping
        // them around helps investigate abuse patterns.
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
            // This returns the number of deleted sessions, and the greatest ULID processed
            let (count, cursor) = repo
                .user_recovery()
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
            debug!("no user recovery sessions to clean up");
        } else {
            info!(count = total, "cleaned up user recovery sessions");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupUserEmailAuthenticationsJob {
    #[tracing::instrument(name = "job.cleanup_user_email_authentications", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Remove email authentications after 7 days. They are in practice only
        // valid for a short time (codes expire after 10 minutes), but keeping
        // them around helps investigate abuse patterns.
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
            // This returns the number of deleted authentications, and the greatest ULID
            // processed
            let (count, cursor) = repo
                .user_email()
                .cleanup_authentications(since, until, BATCH_SIZE)
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
            debug!("no user email authentications to clean up");
        } else {
            info!(count = total, "cleaned up user email authentications");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}
