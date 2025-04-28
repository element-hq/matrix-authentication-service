// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod bound;
mod worker;

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use mas_data_model::{BrowserSession, CompatSession, Session};
use mas_storage::Clock;
use sqlx::PgPool;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use ulid::Ulid;

pub use self::bound::Bound;
use self::worker::Worker;

static MESSAGE_QUEUE_SIZE: usize = 1000;

#[derive(Clone, Copy, Debug, PartialOrd, PartialEq, Eq, Hash)]
enum SessionKind {
    OAuth2,
    Compat,
    Browser,
}

impl SessionKind {
    const fn as_str(self) -> &'static str {
        match self {
            SessionKind::OAuth2 => "oauth2",
            SessionKind::Compat => "compat",
            SessionKind::Browser => "browser",
        }
    }
}

enum Message {
    Record {
        kind: SessionKind,
        id: Ulid,
        date_time: DateTime<Utc>,
        ip: Option<IpAddr>,
    },
    Flush(tokio::sync::oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct ActivityTracker {
    channel: tokio::sync::mpsc::Sender<Message>,
}

impl ActivityTracker {
    /// Create a new activity tracker
    ///
    /// It will spawn the background worker and a loop to flush the tracker on
    /// the task tracker, and both will shut themselves down, flushing one last
    /// time, when the cancellation token is cancelled.
    #[must_use]
    pub fn new(
        pool: PgPool,
        flush_interval: std::time::Duration,
        task_tracker: &TaskTracker,
        cancellation_token: CancellationToken,
    ) -> Self {
        let worker = Worker::new(pool);
        let (sender, receiver) = tokio::sync::mpsc::channel(MESSAGE_QUEUE_SIZE);
        let tracker = ActivityTracker { channel: sender };

        // Spawn the flush loop and the worker
        task_tracker.spawn(
            tracker
                .clone()
                .flush_loop(flush_interval, cancellation_token.clone()),
        );
        task_tracker.spawn(worker.run(receiver, cancellation_token));

        tracker
    }

    /// Bind the activity tracker to an IP address.
    #[must_use]
    pub fn bind(self, ip: Option<IpAddr>) -> Bound {
        Bound::new(self, ip)
    }

    /// Record activity in an OAuth 2.0 session.
    pub async fn record_oauth2_session(
        &self,
        clock: &dyn Clock,
        session: &Session,
        ip: Option<IpAddr>,
    ) {
        let res = self
            .channel
            .send(Message::Record {
                kind: SessionKind::OAuth2,
                id: session.id,
                date_time: clock.now(),
                ip,
            })
            .await;

        if let Err(e) = res {
            tracing::error!("Failed to record OAuth2 session: {}", e);
        }
    }

    /// Record activity in a compat session.
    pub async fn record_compat_session(
        &self,
        clock: &dyn Clock,
        compat_session: &CompatSession,
        ip: Option<IpAddr>,
    ) {
        let res = self
            .channel
            .send(Message::Record {
                kind: SessionKind::Compat,
                id: compat_session.id,
                date_time: clock.now(),
                ip,
            })
            .await;

        if let Err(e) = res {
            tracing::error!("Failed to record compat session: {}", e);
        }
    }

    /// Record activity in a browser session.
    pub async fn record_browser_session(
        &self,
        clock: &dyn Clock,
        browser_session: &BrowserSession,
        ip: Option<IpAddr>,
    ) {
        let res = self
            .channel
            .send(Message::Record {
                kind: SessionKind::Browser,
                id: browser_session.id,
                date_time: clock.now(),
                ip,
            })
            .await;

        if let Err(e) = res {
            tracing::error!("Failed to record browser session: {}", e);
        }
    }

    /// Manually flush the activity tracker.
    pub async fn flush(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let res = self.channel.send(Message::Flush(tx)).await;

        match res {
            Ok(()) => {
                if let Err(e) = rx.await {
                    tracing::error!(
                        error = &e as &dyn std::error::Error,
                        "Failed to flush activity tracker"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    error = &e as &dyn std::error::Error,
                    "Failed to flush activity tracker"
                );
            }
        }
    }

    /// Regularly flush the activity tracker.
    async fn flush_loop(
        self,
        interval: std::time::Duration,
        cancellation_token: CancellationToken,
    ) {
        // This guard on the shutdown token is to ensure that if this task crashes for
        // any reason, the server will shut down
        let _guard = cancellation_token.clone().drop_guard();
        let mut interval = tokio::time::interval(interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                () = cancellation_token.cancelled() => {
                    // The cancellation token was cancelled, so we should exit
                    return;
                }

                // First check if the channel is closed, then check if the timer expired
                () = self.channel.closed() => {
                    // The channel was closed, so we should exit
                    return;
                }


                _ = interval.tick() => {
                    self.flush().await;
                }
            }
        }
    }
}
