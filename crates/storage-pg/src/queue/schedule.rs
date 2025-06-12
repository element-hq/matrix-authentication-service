// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! A module containing the PostgreSQL implementation of the
//! [`QueueScheduleRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_storage::queue::{QueueScheduleRepository, ScheduleStatus};
use sqlx::PgConnection;

use crate::{DatabaseError, ExecuteExt};

/// An implementation of [`QueueScheduleRepository`] for a PostgreSQL
/// connection.
pub struct PgQueueScheduleRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgQueueScheduleRepository<'c> {
    /// Create a new [`PgQueueScheduleRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct ScheduleLookup {
    schedule_name: String,
    last_scheduled_at: Option<DateTime<Utc>>,
    last_scheduled_job_completed: Option<bool>,
}

impl From<ScheduleLookup> for ScheduleStatus {
    fn from(value: ScheduleLookup) -> Self {
        ScheduleStatus {
            schedule_name: value.schedule_name,
            last_scheduled_at: value.last_scheduled_at,
            last_scheduled_job_completed: value.last_scheduled_job_completed,
        }
    }
}

#[async_trait]
impl QueueScheduleRepository for PgQueueScheduleRepository<'_> {
    type Error = DatabaseError;

    async fn setup(&mut self, schedules: &[&'static str]) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
                INSERT INTO queue_schedules (schedule_name)
                SELECT * FROM UNNEST($1::text[]) AS t (schedule_name)
                ON CONFLICT (schedule_name) DO NOTHING
            "#,
            &schedules.iter().map(|&s| s.to_owned()).collect::<Vec<_>>(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }

    async fn list(&mut self) -> Result<Vec<ScheduleStatus>, Self::Error> {
        let res = sqlx::query_as!(
            ScheduleLookup,
            r#"
                SELECT
                    queue_schedules.schedule_name as "schedule_name!",
                    queue_schedules.last_scheduled_at,
                    queue_jobs.status IN ('completed', 'failed') as last_scheduled_job_completed
                FROM queue_schedules
                LEFT JOIN queue_jobs
                    ON queue_jobs.queue_job_id = queue_schedules.last_scheduled_job_id
            "#
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        Ok(res.into_iter().map(Into::into).collect())
    }
}
