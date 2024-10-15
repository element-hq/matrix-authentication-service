// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! A module containing the PostgreSQL implementation of the
//! [`QueueJobRepository`].

use async_trait::async_trait;
use mas_storage::{queue::QueueJobRepository, Clock};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, ExecuteExt};

/// An implementation of [`QueueJobRepository`] for a PostgreSQL connection.
pub struct PgQueueJobRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgQueueJobRepository<'c> {
    /// Create a new [`PgQueueJobRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl<'c> QueueJobRepository for PgQueueJobRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.queue_job.schedule",
        fields(
            queue_job.id,
            queue_job.queue_name = queue_name,
            db.query.text,
        ),
        skip_all,
        err,
    )]
    async fn schedule(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        queue_name: &str,
        payload: serde_json::Value,
        metadata: serde_json::Value,
    ) -> Result<(), Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("queue_job.id", tracing::field::display(id));

        sqlx::query!(
            r#"
                INSERT INTO queue_jobs
                    (queue_job_id, queue_name, payload, metadata, created_at)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            queue_name,
            payload,
            metadata,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }
}
