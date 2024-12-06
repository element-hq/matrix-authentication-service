// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use chrono::{DateTime, Duration, Utc};
use mas_storage::{queue::Worker, Clock, RepositoryAccess, RepositoryError};
use mas_storage_pg::{DatabaseError, PgRepository};
use rand::{distributions::Uniform, Rng};
use rand_chacha::ChaChaRng;
use sqlx::{
    postgres::{PgAdvisoryLock, PgListener},
    Acquire, Either,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::State;

#[derive(Debug, Error)]
pub enum QueueRunnerError {
    #[error("Failed to setup listener")]
    SetupListener(#[source] sqlx::Error),

    #[error("Failed to start transaction")]
    StartTransaction(#[source] sqlx::Error),

    #[error("Failed to commit transaction")]
    CommitTransaction(#[source] sqlx::Error),

    #[error("Failed to acquire leader lock")]
    LeaderLock(#[source] sqlx::Error),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[error("Worker is not the leader")]
    NotLeader,
}

// When the worker waits for a notification, we still want to wake it up every
// second. Because we don't want all the workers to wake up at the same time, we
// add a random jitter to the sleep duration, so they effectively sleep between
// 0.9 and 1.1 seconds.
const MIN_SLEEP_DURATION: std::time::Duration = std::time::Duration::from_millis(900);
const MAX_SLEEP_DURATION: std::time::Duration = std::time::Duration::from_millis(1100);

pub struct QueueWorker {
    rng: ChaChaRng,
    clock: Box<dyn Clock + Send>,
    listener: PgListener,
    registration: Worker,
    am_i_leader: bool,
    last_heartbeat: DateTime<Utc>,
    cancellation_token: CancellationToken,
}

impl QueueWorker {
    #[tracing::instrument(
        name = "worker.init",
        skip_all,
        fields(worker.id)
    )]
    pub async fn new(
        state: State,
        cancellation_token: CancellationToken,
    ) -> Result<Self, QueueRunnerError> {
        let mut rng = state.rng();
        let clock = state.clock();

        let mut listener = PgListener::connect_with(state.pool())
            .await
            .map_err(QueueRunnerError::SetupListener)?;

        // We get notifications of leader stepping down on this channel
        listener
            .listen("queue_leader_stepdown")
            .await
            .map_err(QueueRunnerError::SetupListener)?;

        let txn = listener
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
            listener,
            registration,
            am_i_leader: false,
            last_heartbeat: now,
            cancellation_token,
        })
    }

    pub async fn run(&mut self) -> Result<(), QueueRunnerError> {
        while !self.cancellation_token.is_cancelled() {
            self.run_loop().await?;
        }

        self.shutdown().await?;

        Ok(())
    }

    #[tracing::instrument(name = "worker.run_loop", skip_all, err)]
    async fn run_loop(&mut self) -> Result<(), QueueRunnerError> {
        self.wait_until_wakeup().await?;

        if self.cancellation_token.is_cancelled() {
            return Ok(());
        }

        self.tick().await?;

        if self.am_i_leader {
            self.perform_leader_duties().await?;
        }

        Ok(())
    }

    #[tracing::instrument(name = "worker.shutdown", skip_all, err)]
    async fn shutdown(&mut self) -> Result<(), QueueRunnerError> {
        tracing::info!("Shutting down worker");

        // Start a transaction on the existing PgListener connection
        let txn = self
            .listener
            .begin()
            .await
            .map_err(QueueRunnerError::StartTransaction)?;

        let mut repo = PgRepository::from_conn(txn);

        // Tell the other workers we're shutting down
        // This also releases the leader election lease
        repo.queue_worker()
            .shutdown(&self.clock, &self.registration)
            .await?;

        repo.into_inner()
            .commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

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
        let wakeup_sleep = tokio::time::sleep(sleep_duration);

        tokio::select! {
            () = self.cancellation_token.cancelled() => {
                tracing::debug!("Woke up from cancellation");
            },

            () = wakeup_sleep => {
                tracing::debug!("Woke up from sleep");
            },

            notification = self.listener.recv() => {
                match notification {
                    Ok(notification) => {
                        tracing::debug!(
                            notification.channel = notification.channel(),
                            notification.payload = notification.payload(),
                            "Woke up from notification"
                        );
                    },
                    Err(e) => {
                        tracing::error!(error = &e as &dyn std::error::Error, "Failed to receive notification");
                    },
                }
            },
        }

        Ok(())
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

        // Start a transaction on the existing PgListener connection
        let txn = self
            .listener
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

        // After this point, we are locking the leader table, so it's important that we
        // commit as soon as possible to not block the other workers for too long
        repo.into_inner()
            .commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

        // Save the new leader state to log any change
        if leader != self.am_i_leader {
            // If we flipped state, log it
            self.am_i_leader = leader;
            if self.am_i_leader {
                tracing::info!("I'm the leader now");
            } else {
                tracing::warn!("I am no longer the leader");
            }
        }

        Ok(())
    }

    #[tracing::instrument(name = "worker.perform_leader_duties", skip_all, err)]
    async fn perform_leader_duties(&mut self) -> Result<(), QueueRunnerError> {
        // This should have been checked by the caller, but better safe than sorry
        if !self.am_i_leader {
            return Err(QueueRunnerError::NotLeader);
        }

        // Start a transaction on the existing PgListener connection
        let txn = self
            .listener
            .begin()
            .await
            .map_err(QueueRunnerError::StartTransaction)?;

        // The thing with the leader election is that it locks the table during the
        // election, preventing other workers from going through the loop.
        //
        // Ideally, we would do the leader duties in the same transaction so that we
        // make sure only one worker is doing the leader duties, but that
        // would mean we would lock all the workers for the duration of the
        // duties, which is not ideal.
        //
        // So we do the duties in a separate transaction, in which we take an advisory
        // lock, so that in the very rare case where two workers think they are the
        // leader, we still don't have two workers doing the duties at the same time.
        let lock = PgAdvisoryLock::new("leader-duties");

        let locked = lock
            .try_acquire(txn)
            .await
            .map_err(QueueRunnerError::LeaderLock)?;

        let locked = match locked {
            Either::Left(locked) => locked,
            Either::Right(txn) => {
                tracing::error!("Another worker has the leader lock, aborting");
                txn.rollback()
                    .await
                    .map_err(QueueRunnerError::CommitTransaction)?;
                return Ok(());
            }
        };

        let mut repo = PgRepository::from_conn(locked);

        // We also check if the worker is dead, and if so, we shutdown all the dead
        // workers that haven't checked in the last two minutes
        repo.queue_worker()
            .shutdown_dead_workers(&self.clock, Duration::minutes(2))
            .await?;

        // Release the leader lock
        let txn = repo
            .into_inner()
            .release_now()
            .await
            .map_err(QueueRunnerError::LeaderLock)?;

        txn.commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

        Ok(())
    }
}
