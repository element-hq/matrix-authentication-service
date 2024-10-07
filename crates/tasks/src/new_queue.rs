// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use chrono::Duration;
use mas_storage::{RepositoryAccess, RepositoryError};

use crate::State;

pub async fn run(state: State) -> Result<(), RepositoryError> {
    let span = tracing::info_span!("worker.init", worker.id = tracing::field::Empty);
    let guard = span.enter();
    let mut repo = state.repository().await?;
    let mut rng = state.rng();
    let clock = state.clock();

    let mut worker = repo.queue_worker().register(&mut rng, &clock).await?;
    span.record("worker.id", tracing::field::display(worker.id));
    repo.save().await?;

    tracing::info!("Registered worker");
    drop(guard);

    let mut was_i_the_leader = false;

    // Record when we last sent a heartbeat
    let mut last_heartbeat = clock.now();

    loop {
        // This is to make sure we wake up every second to do the maintenance tasks
        // Later we might wait on other events, like a PG notification
        let wakeup_sleep = tokio::time::sleep(std::time::Duration::from_secs(1));
        wakeup_sleep.await;

        let span = tracing::info_span!("worker.tick", %worker.id);
        let _guard = span.enter();

        tracing::debug!("Tick");
        let now = clock.now();
        let mut repo = state.repository().await?;

        // We send a heartbeat every minute, to avoid writing to the database too often
        // on a logged table
        if now - last_heartbeat >= chrono::Duration::minutes(1) {
            tracing::info!("Sending heartbeat");
            worker = repo.queue_worker().heartbeat(&clock, worker).await?;
            last_heartbeat = now;
        }

        // Remove any dead worker leader leases
        repo.queue_worker()
            .remove_leader_lease_if_expired(&clock)
            .await?;

        // Try to become (or stay) the leader
        let am_i_the_leader = repo
            .queue_worker()
            .try_get_leader_lease(&clock, &worker)
            .await?;

        // Log any changes in leadership
        if !was_i_the_leader && am_i_the_leader {
            tracing::info!("I'm the leader now");
        } else if was_i_the_leader && !am_i_the_leader {
            tracing::warn!("I am no longer the leader");
        }
        was_i_the_leader = am_i_the_leader;

        // The leader does all the maintenance work
        if am_i_the_leader {
            // We also check if the worker is dead, and if so, we shutdown all the dead
            // workers that haven't checked in the last two minutes
            repo.queue_worker()
                .shutdown_dead_workers(&clock, Duration::minutes(2))
                .await?;
        }

        repo.save().await?;
    }
}
