// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::time::Duration;

use tokio::signal::unix::{Signal, SignalKind};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// A helper to manage graceful shutdowns and track tasks that gracefully
/// shutdown.
///
/// It will listen for SIGTERM and SIGINT signals, and will trigger a soft
/// shutdown on the first signal, and a hard shutdown on the second signal or
/// after a timeout.
///
/// Users of this manager should use the `soft_shutdown_token` to react to a
/// soft shutdown, which should gracefully finish requests and close
/// connections, and the `hard_shutdown_token` to react to a hard shutdown,
/// which should drop all connections and finish all requests.
///
/// They should also use the `task_tracker` to make it track things running, so
/// that it knows when the soft shutdown is over and worked.
pub struct ShutdownManager {
    hard_shutdown_token: CancellationToken,
    soft_shutdown_token: CancellationToken,
    task_tracker: TaskTracker,
    sigterm: Signal,
    sigint: Signal,
    timeout: Duration,
}

impl ShutdownManager {
    /// Create a new shutdown manager, installing the signal handlers
    ///
    /// # Errors
    ///
    /// Returns an error if the signal handler could not be installed
    pub fn new() -> Result<Self, std::io::Error> {
        let hard_shutdown_token = CancellationToken::new();
        let soft_shutdown_token = hard_shutdown_token.child_token();
        let sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
        let sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
        let timeout = Duration::from_secs(60);
        let task_tracker = TaskTracker::new();

        Ok(Self {
            hard_shutdown_token,
            soft_shutdown_token,
            task_tracker,
            sigterm,
            sigint,
            timeout,
        })
    }

    /// Get a reference to the task tracker
    #[must_use]
    pub fn task_tracker(&self) -> &TaskTracker {
        &self.task_tracker
    }

    /// Get a cancellation token that can be used to react to a hard shutdown
    #[must_use]
    pub fn hard_shutdown_token(&self) -> CancellationToken {
        self.hard_shutdown_token.clone()
    }

    /// Get a cancellation token that can be used to react to a soft shutdown
    #[must_use]
    pub fn soft_shutdown_token(&self) -> CancellationToken {
        self.soft_shutdown_token.clone()
    }

    /// Run until we finish completely shutting down.
    pub async fn run(mut self) {
        // Wait for a first signal and trigger the soft shutdown
        tokio::select! {
            _ = self.sigterm.recv() => {
                tracing::info!("Shutdown signal received (SIGTERM), shutting down");
            },
            _ = self.sigint.recv() => {
                tracing::info!("Shutdown signal received (SIGINT), shutting down");
            },
        };

        self.soft_shutdown_token.cancel();
        self.task_tracker.close();

        // Start the timeout
        let timeout = tokio::time::sleep(self.timeout);
        tokio::select! {
            _ = self.sigterm.recv() => {
                tracing::warn!("Second shutdown signal received (SIGTERM), abort");
            },
            _ = self.sigint.recv() => {
                tracing::warn!("Second shutdown signal received (SIGINT), abort");
            },
            () = timeout => {
                tracing::warn!("Shutdown timeout reached, abort");
            },
            () = self.task_tracker.wait() => {
                // This is the "happy path", we have gracefully shutdown
            },
        }

        self.hard_shutdown_token().cancel();

        // TODO: we may want to have a time out on the task tracker, in case we have
        // really stuck tasks on it
        self.task_tracker().wait().await;

        tracing::info!("All tasks are done, exitting");
    }
}
