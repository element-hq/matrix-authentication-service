// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use chrono::{DateTime, Duration, Utc};
use mas_storage::{queue::Worker, Clock, RepositoryAccess, RepositoryError};
use mas_storage_pg::{DatabaseError, PgRepository};
use rand::{distributions::Uniform, Rng};
use rand_chacha::ChaChaRng;
use sqlx::PgPool;
use thiserror::Error;

use crate::State;

#[derive(Debug, Error)]
pub enum QueueRunnerError {
    #[error("Failed to setup listener")]
    SetupListener(#[source] sqlx::Error),

    #[error("Failed to start transaction")]
    StartTransaction(#[source] sqlx::Error),

    #[error("Failed to commit transaction")]
    CommitTransaction(#[source] sqlx::Error),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[error("Worker is not the leader")]
    NotLeader,
}

const MIN_SLEEP_DURATION: std::time::Duration = std::time::Duration::from_millis(900);
const MAX_SLEEP_DURATION: std::time::Duration = std::time::Duration::from_millis(1100);

pub struct QueueWorker {
    rng: ChaChaRng,
    clock: Box<dyn Clock + Send>,
    pool: PgPool,
    registration: Worker,
    am_i_leader: bool,
    last_heartbeat: DateTime<Utc>,
}

impl QueueWorker {
    #[tracing::instrument(
        name = "worker.init",
        skip_all,
        fields(worker.id)
    )]
    pub async fn new(state: State) -> Result<Self, QueueRunnerError> {
        let mut rng = state.rng();
        let clock = state.clock();
        let pool = state.pool().clone();

        let txn = pool
            .begin()
            .await
            .map_err(QueueRunnerError::StartTransaction)?;
        let mut repo = PgRepository::from_conn(txn);

        let registration = repo.queue_worker().register(&mut rng, &clock).await?;
        tracing::Span::current().record("worker.id", tracing::field::display(registration.id));
        repo.into_inner()
            .commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

        tracing::info!("Registered worker");
        let now = clock.now();

        Ok(Self {
            rng,
            clock,
            pool,
            registration,
            am_i_leader: false,
            last_heartbeat: now,
        })
    }

    pub async fn run(&mut self) -> Result<(), QueueRunnerError> {
        loop {
            self.run_loop().await?;
        }
    }

    #[tracing::instrument(name = "worker.run_loop", skip_all, err)]
    async fn run_loop(&mut self) -> Result<(), QueueRunnerError> {
        self.wait_until_wakeup().await?;
        self.tick().await?;

        if self.am_i_leader {
            self.perform_leader_duties().await?;
        }

        Ok(())
    }

    #[tracing::instrument(name = "worker.wait_until_wakeup", skip_all, err)]
    async fn wait_until_wakeup(&mut self) -> Result<(), QueueRunnerError> {
        // This is to make sure we wake up every second to do the maintenance tasks
        // We add a little bit of random jitter to the duration, so that we don't get
        // fully synced workers waking up at the same time after each notification
        let sleep_duration = self
            .rng
            .sample(Uniform::new(MIN_SLEEP_DURATION, MAX_SLEEP_DURATION));
        tokio::time::sleep(sleep_duration).await;
        tracing::debug!("Woke up from sleep");

        Ok(())
    }

    fn set_new_leader_state(&mut self, state: bool) {
        // Do nothing if we were already on that state
        if state == self.am_i_leader {
            return;
        }

        // If we flipped state, log it
        self.am_i_leader = state;
        if self.am_i_leader {
            tracing::info!("I'm the leader now");
        } else {
            tracing::warn!("I am no longer the leader");
        }
    }

    #[tracing::instrument(
        name = "worker.tick",
        skip_all,
        fields(worker.id = %self.registration.id),
        err,
    )]
    async fn tick(&mut self) -> Result<(), QueueRunnerError> {
        tracing::debug!("Tick");
        let now = self.clock.now();

        let txn = self
            .pool
            .begin()
            .await
            .map_err(QueueRunnerError::StartTransaction)?;
        let mut repo = PgRepository::from_conn(txn);

        // We send a heartbeat every minute, to avoid writing to the database too often
        // on a logged table
        if now - self.last_heartbeat >= chrono::Duration::minutes(1) {
            tracing::info!("Sending heartbeat");
            repo.queue_worker()
                .heartbeat(&self.clock, &self.registration)
                .await?;
            self.last_heartbeat = now;
        }

        // Remove any dead worker leader leases
        repo.queue_worker()
            .remove_leader_lease_if_expired(&self.clock)
            .await?;

        // Try to become (or stay) the leader
        let leader = repo
            .queue_worker()
            .try_get_leader_lease(&self.clock, &self.registration)
            .await?;

        repo.into_inner()
            .commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

        // Save the new leader state
        self.set_new_leader_state(leader);

        Ok(())
    }

    #[tracing::instrument(name = "worker.perform_leader_duties", skip_all, err)]
    async fn perform_leader_duties(&mut self) -> Result<(), QueueRunnerError> {
        // This should have been checked by the caller, but better safe than sorry
        if !self.am_i_leader {
            return Err(QueueRunnerError::NotLeader);
        }

        let txn = self
            .pool
            .begin()
            .await
            .map_err(QueueRunnerError::StartTransaction)?;
        let mut repo = PgRepository::from_conn(txn);

        // We also check if the worker is dead, and if so, we shutdown all the dead
        // workers that haven't checked in the last two minutes
        repo.queue_worker()
            .shutdown_dead_workers(&self.clock, Duration::minutes(2))
            .await?;

        repo.into_inner()
            .commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

        Ok(())
    }
}
