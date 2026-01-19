// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Database-related tasks

use std::time::Duration;

use async_trait::async_trait;
use mas_storage::queue::{
    CleanupConsumedOAuthRefreshTokensJob, CleanupExpiredOAuthAccessTokensJob,
    CleanupFinishedCompatSessionsJob, CleanupOAuthAuthorizationGrantsJob,
    CleanupOAuthDeviceCodeGrantsJob, CleanupRevokedOAuthAccessTokensJob,
    CleanupRevokedOAuthRefreshTokensJob, CleanupUserEmailAuthenticationsJob,
    CleanupUserRecoverySessionsJob, CleanupUserRegistrationsJob, PruneStalePolicyDataJob,
};
use tracing::{debug, info};
use ulid::Ulid;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

const BATCH_SIZE: usize = 1000;

#[async_trait]
impl RunnableJob for CleanupRevokedOAuthAccessTokensJob {
    #[tracing::instrument(name = "job.cleanup_revoked_oauth_access_tokens", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Cleanup tokens that were revoked more than an hour ago
        let until = state.clock.now() - chrono::Duration::hours(1);
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            // This returns the number of deleted tokens, and the last revoked_at timestamp
            let (count, last_revoked_at) = repo
                .oauth2_access_token()
                .cleanup_revoked(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_revoked_at;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_SIZE,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no token to clean up");
        } else {
            info!(count = total, "cleaned up revoked tokens");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupExpiredOAuthAccessTokensJob {
    #[tracing::instrument(name = "job.cleanup_expired_oauth_access_tokens", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Cleanup tokens that expired more than a month ago
        // It is important to keep them around for a bit because of refresh
        // token idempotency. When we see a refresh token twice, we allow
        // reusing it *only* if both the next refresh token and the next access
        // tokens were not used. By keeping expired access tokens around for a
        // month, we cannot make the *correct* decision, we will assume that the
        // token wasn't used. Refer to the token refresh logic for details.
        let until = state.clock.now() - chrono::Duration::days(30);
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            // This returns the number of deleted tokens, and the last expires_at timestamp
            let (count, last_expires_at) = repo
                .oauth2_access_token()
                .cleanup_expired(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_expires_at;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_SIZE,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no token to clean up");
        } else {
            info!(count = total, "cleaned up expired tokens");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(60))
    }
}

#[async_trait]
impl RunnableJob for CleanupRevokedOAuthRefreshTokensJob {
    #[tracing::instrument(name = "job.cleanup_revoked_oauth_refresh_tokens", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Cleanup tokens that were revoked more than an hour ago
        let until = state.clock.now() - chrono::Duration::hours(1);
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            // This returns the number of deleted tokens, and the last revoked_at timestamp
            let (count, last_revoked_at) = repo
                .oauth2_refresh_token()
                .cleanup_revoked(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_revoked_at;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_SIZE,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no token to clean up");
        } else {
            info!(count = total, "cleaned up revoked tokens");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        // This job runs every hour, so having it running it for 10 minutes is fine
        Some(Duration::from_secs(10 * 60))
    }
}

#[async_trait]
impl RunnableJob for CleanupConsumedOAuthRefreshTokensJob {
    #[tracing::instrument(name = "job.cleanup_consumed_oauth_refresh_tokens", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Cleanup tokens that were consumed more than an hour ago
        let until = state.clock.now() - chrono::Duration::hours(1);
        let mut total = 0;

        // Run until we get cancelled. We don't schedule a retry if we get cancelled, as
        // this is a scheduled job and it will end up being rescheduled later anyway.
        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            // This returns the number of deleted tokens, and the last consumed_at timestamp
            let (count, last_consumed_at) = repo
                .oauth2_refresh_token()
                .cleanup_consumed(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_consumed_at;
            total += count;

            // Check how many we deleted. If we deleted exactly BATCH_SIZE,
            // there might be more to delete
            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no token to clean up");
        } else {
            info!(count = total, "cleaned up consumed tokens");
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
impl RunnableJob for PruneStalePolicyDataJob {
    #[tracing::instrument(name = "job.prune_stale_policy_data", skip_all)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        // Keep the last 10 policy data
        let count = repo
            .policy_data()
            .prune(10)
            .await
            .map_err(JobError::retry)?;

        repo.save().await.map_err(JobError::retry)?;

        if count == 0 {
            debug!("no stale policy data to prune");
        } else {
            info!(count, "pruned stale policy data");
        }

        Ok(())
    }
}
