// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Database-related tasks

use std::str::FromStr;

use apalis::utils::TokioExecutor;
use apalis_core::{
    builder::{WorkerBuilder, WorkerFactoryFn},
    layers::extensions::Data,
    monitor::Monitor,
};
use apalis_cron::CronStream;
use chrono::{DateTime, Utc};
use mas_storage::{
    job::TaskNamespace, oauth2::OAuth2AccessTokenRepository, RepositoryAccess, RepositoryError,
};
use tracing::{debug, info};

use crate::{
    utils::{metrics_layer, trace_layer, TracedJob},
    State,
};

#[derive(Default, Clone)]
pub struct CleanupExpiredTokensJob {
    scheduled: DateTime<Utc>,
}

impl From<DateTime<Utc>> for CleanupExpiredTokensJob {
    fn from(scheduled: DateTime<Utc>) -> Self {
        Self { scheduled }
    }
}

impl TaskNamespace for CleanupExpiredTokensJob {
    const NAMESPACE: &'static str = "cleanup-expired-tokens";
}

impl TracedJob for CleanupExpiredTokensJob {}

pub async fn cleanup_expired_tokens(
    job: CleanupExpiredTokensJob,
    state: Data<State>,
) -> Result<(), RepositoryError> {
    debug!("cleanup expired tokens job scheduled at {}", job.scheduled);

    let clock = state.clock();
    let mut repo = state
        .repository()
        .await
        .map_err(RepositoryError::from_error)?;

    let count = repo.oauth2_access_token().cleanup_expired(&clock).await?;
    repo.save().await?;

    if count == 0 {
        debug!("no token to clean up");
    } else {
        info!(count, "cleaned up expired tokens");
    }

    Ok(())
}

pub(crate) fn register(monitor: Monitor<TokioExecutor>, state: &State) -> Monitor<TokioExecutor> {
    let schedule = apalis_cron::Schedule::from_str("*/15 * * * * *").unwrap();
    let worker_name = state.worker_name::<CleanupExpiredTokensJob>();
    let worker = WorkerBuilder::new(worker_name)
        .data(state.clone())
        .layer(metrics_layer())
        .layer(trace_layer())
        .backend(CronStream::new(schedule))
        .build_fn(cleanup_expired_tokens);

    monitor.register(worker)
}
