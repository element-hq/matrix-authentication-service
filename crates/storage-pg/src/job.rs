// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! A module containing the PostgreSQL implementation of the [`JobRepository`].

use async_trait::async_trait;
use mas_storage::job::{JobId, JobRepository, JobSubmission};
use sqlx::PgConnection;

use crate::{DatabaseError, ExecuteExt};

/// An implementation of [`JobRepository`] for a PostgreSQL connection.
pub struct PgJobRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgJobRepository<'c> {
    /// Create a new [`PgJobRepository`] from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl<'c> JobRepository for PgJobRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.job.schedule_submission",
        skip_all,
        fields(
            db.query.text,
            job.id,
            job.name = submission.name(),
        ),
        err,
    )]
    async fn schedule_submission(
        &mut self,
        submission: JobSubmission,
    ) -> Result<JobId, Self::Error> {
        // XXX: This does not use the clock nor the rng
        let id = JobId::new();
        tracing::Span::current().record("job.id", tracing::field::display(&id));

        let res = sqlx::query!(
            r#"
                INSERT INTO apalis.jobs (job, id, job_type)
                VALUES ($1::json, $2::text, $3::text)
            "#,
            submission.payload(),
            id.to_string(),
            submission.name(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(id)
    }
}
