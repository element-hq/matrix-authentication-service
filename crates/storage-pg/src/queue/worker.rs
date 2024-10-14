// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! A module containing the PostgreSQL implementation of the
//! [`QueueWorkerRepository`].

use async_trait::async_trait;
use chrono::Duration;
use mas_storage::{
    queue::{QueueWorkerRepository, Worker},
    Clock,
};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, ExecuteExt};

/// An implementation of [`QueueWorkerRepository`] for a PostgreSQL connection.
pub struct PgQueueWorkerRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgQueueWorkerRepository<'c> {
    /// Create a new [`PgQueueWorkerRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl<'c> QueueWorkerRepository for PgQueueWorkerRepository<'c> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.queue_worker.register",
        skip_all,
        fields(
            worker.id,
            db.query.text,
        ),
        err,
    )]
    async fn register(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
    ) -> Result<Worker, Self::Error> {
        let now = clock.now();
        let worker_id = Ulid::from_datetime_with_source(now.into(), rng);
        tracing::Span::current().record("worker.id", tracing::field::display(worker_id));

        sqlx::query!(
            r#"
                INSERT INTO queue_workers (queue_worker_id, registered_at, last_seen_at)
                VALUES ($1, $2, $2)
            "#,
            Uuid::from(worker_id),
            now,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(Worker { id: worker_id })
    }

    #[tracing::instrument(
        name = "db.queue_worker.heartbeat",
        skip_all,
        fields(
            %worker.id,
            db.query.text,
        ),
        err,
    )]
    async fn heartbeat(&mut self, clock: &dyn Clock, worker: &Worker) -> Result<(), Self::Error> {
        let now = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE queue_workers
                SET last_seen_at = $2
                WHERE queue_worker_id = $1 AND shutdown_at IS NULL
            "#,
            Uuid::from(worker.id),
            now,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        // If no row was updated, the worker was shutdown so we return an error
        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.shutdown",
        skip_all,
        fields(
            %worker.id,
            db.query.text,
        ),
        err,
    )]
    async fn shutdown(&mut self, clock: &dyn Clock, worker: &Worker) -> Result<(), Self::Error> {
        let now = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE queue_workers
                SET shutdown_at = $2
                WHERE queue_worker_id = $1
            "#,
            Uuid::from(worker.id),
            now,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        // Remove the leader lease if we were holding it
        let res = sqlx::query!(
            r#"
                DELETE FROM queue_leader
                WHERE queue_worker_id = $1
            "#,
            Uuid::from(worker.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        // If we were holding the leader lease, notify workers
        if res.rows_affected() > 0 {
            sqlx::query!(
                r#"
                    NOTIFY queue_leader_stepdown
                "#,
            )
            .traced()
            .execute(&mut *self.conn)
            .await?;
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.shutdown_dead_workers",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn shutdown_dead_workers(
        &mut self,
        clock: &dyn Clock,
        threshold: Duration,
    ) -> Result<(), Self::Error> {
        let now = clock.now();
        sqlx::query!(
            r#"
                UPDATE queue_workers
                SET shutdown_at = $1
                WHERE shutdown_at IS NULL
                  AND last_seen_at < $2
            "#,
            now,
            now - threshold,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.remove_leader_lease_if_expired",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn remove_leader_lease_if_expired(
        &mut self,
        clock: &dyn Clock,
    ) -> Result<(), Self::Error> {
        let now = clock.now();
        sqlx::query!(
            r#"
                DELETE FROM queue_leader
                WHERE expires_at < $1
            "#,
            now,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.queue_worker.try_get_leader_lease",
        skip_all,
        fields(
            %worker.id,
            db.query.text,
        ),
        err,
    )]
    async fn try_get_leader_lease(
        &mut self,
        clock: &dyn Clock,
        worker: &Worker,
    ) -> Result<bool, Self::Error> {
        let now = clock.now();
        let ttl = Duration::seconds(5);
        // The queue_leader table is meant to only have a single row, which conflicts on
        // the `active` column

        // If there is a conflict, we update the `expires_at` column ONLY IF the current
        // leader is ourselves.
        let res = sqlx::query!(
            r#"
                INSERT INTO queue_leader (elected_at, expires_at, queue_worker_id)
                VALUES ($1, $2, $3)
                ON CONFLICT (active)
                DO UPDATE SET expires_at = EXCLUDED.expires_at
                WHERE queue_leader.queue_worker_id = $3
            "#,
            now,
            now + ttl,
            Uuid::from(worker.id)
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        // We can then detect whether we are the leader or not by checking how many rows
        // were affected by the upsert
        let am_i_the_leader = res.rows_affected() == 1;

        Ok(am_i_the_leader)
    }
}
