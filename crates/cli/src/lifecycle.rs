// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{process::ExitCode, time::Duration};

use futures_util::future::{BoxFuture, Either};
use mas_handlers::ActivityTracker;
use mas_templates::Templates;
use tokio::signal::unix::{Signal, SignalKind};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// A helper to manage the lifecycle of the service, inclusing handling graceful
/// shutdowns and configuration reloads.
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
///
/// It also integrates with [`sd_notify`] to notify the service manager of the
/// state of the service.
pub struct LifecycleManager {
    hard_shutdown_token: CancellationToken,
    soft_shutdown_token: CancellationToken,
    task_tracker: TaskTracker,
    sigterm: Signal,
    sigint: Signal,
    sighup: Signal,
    timeout: Duration,
    reload_handlers: Vec<Box<dyn Fn() -> BoxFuture<'static, ()>>>,
}

/// Represents a thing that can be reloaded with a SIGHUP
pub trait Reloadable: Clone + Send {
    fn reload(&self) -> impl Future<Output = ()> + Send;
}

impl Reloadable for ActivityTracker {
    async fn reload(&self) {
        self.flush().await;
    }
}

impl Reloadable for Templates {
    async fn reload(&self) {
        if let Err(err) = self.reload().await {
            tracing::error!(
                error = &err as &dyn std::error::Error,
                "Failed to reload templates"
            );
        }
    }
}

/// A wrapper around [`sd_notify::notify`] that logs any errors
fn notify(states: &[sd_notify::NotifyState]) {
    if let Err(e) = sd_notify::notify(false, states) {
        tracing::error!(
            error = &e as &dyn std::error::Error,
            "Failed to notify service manager"
        );
    }
}

impl LifecycleManager {
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
        let sighup = tokio::signal::unix::signal(SignalKind::hangup())?;
        let timeout = Duration::from_secs(60);
        let task_tracker = TaskTracker::new();

        notify(&[sd_notify::NotifyState::MainPid(std::process::id())]);

        Ok(Self {
            hard_shutdown_token,
            soft_shutdown_token,
            task_tracker,
            sigterm,
            sigint,
            sighup,
            timeout,
            reload_handlers: Vec::new(),
        })
    }

    /// Add a handler to be called when the server gets a SIGHUP
    pub fn register_reloadable(&mut self, reloadable: &(impl Reloadable + 'static)) {
        let reloadable = reloadable.clone();
        self.reload_handlers.push(Box::new(move || {
            let reloadable = reloadable.clone();
            Box::pin(async move { reloadable.reload().await })
        }));
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
    pub async fn run(mut self) -> ExitCode {
        notify(&[sd_notify::NotifyState::Ready]);

        // This will be `Some` if we have the watchdog enabled, and `None` if not
        let mut watchdog_interval = {
            let mut watchdog_usec = 0;
            if sd_notify::watchdog_enabled(false, &mut watchdog_usec) {
                Some(tokio::time::interval(Duration::from_micros(
                    watchdog_usec / 2,
                )))
            } else {
                None
            }
        };

        // Wait for a first shutdown signal and trigger the soft shutdown
        let likely_crashed = loop {
            // This makes a Future that will either yield the watchdog tick if enabled, or a
            // pending Future if not
            let watchdog_tick = if let Some(watchdog_interval) = &mut watchdog_interval {
                Either::Left(watchdog_interval.tick())
            } else {
                Either::Right(futures_util::future::pending())
            };

            tokio::select! {
                () = self.soft_shutdown_token.cancelled() => {
                    tracing::warn!("Another task triggered a shutdown, it likely crashed! Shutting down");
                    break true;
                },

                _ = self.sigterm.recv() => {
                    tracing::info!("Shutdown signal received (SIGTERM), shutting down");
                    break false;
                },

                _ = self.sigint.recv() => {
                    tracing::info!("Shutdown signal received (SIGINT), shutting down");
                    break false;
                },

                _ = watchdog_tick => {
                    notify(&[
                        sd_notify::NotifyState::Watchdog,
                    ]);
                },

                _ = self.sighup.recv() => {
                    tracing::info!("Reload signal received (SIGHUP), reloading");

                    notify(&[
                        sd_notify::NotifyState::Reloading,
                        sd_notify::NotifyState::monotonic_usec_now()
                            .expect("Failed to read monotonic clock")
                    ]);

                    // XXX: if one handler takes a long time, it will block the
                    // rest of the shutdown process, which is not ideal. We
                    // should probably have a timeout here
                    futures_util::future::join_all(
                        self.reload_handlers
                            .iter()
                            .map(|handler| handler())
                    ).await;

                    notify(&[sd_notify::NotifyState::Ready]);

                    tracing::info!("Reloading done");
                },
            }
        };

        notify(&[sd_notify::NotifyState::Stopping]);

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

        if likely_crashed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    }
}
