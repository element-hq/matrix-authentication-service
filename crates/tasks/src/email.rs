// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use mas_storage::queue::VerifyEmailJob;

use crate::{
    new_queue::{JobContext, JobError, RunnableJob},
    State,
};

#[async_trait]
impl RunnableJob for VerifyEmailJob {
    #[tracing::instrument(
        name = "job.verify_email",
        fields(user_email.id = %self.user_email_id()),
        skip_all,
        err,
    )]
    async fn run(&self, _state: &State, _context: JobContext) -> Result<(), JobError> {
        // This job was for the old email verification flow, which has been replaced.
        // We still want to consume existing jobs in the queue, so we just make them
        // permanently fail.
        Err(JobError::fail(anyhow::anyhow!("Not implemented")))
    }
}
