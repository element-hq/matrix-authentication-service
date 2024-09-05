// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{collections::HashMap, net::IpAddr};

use chrono::{DateTime, Utc};
use mas_storage::{user::BrowserSessionRepository, RepositoryAccess};
use opentelemetry::{
    metrics::{Counter, Histogram},
    Key,
};
use sqlx::PgPool;
use ulid::Ulid;

use crate::activity_tracker::{Message, SessionKind};

/// The maximum number of pending activity records before we flush them to the
/// database automatically.
///
/// The [`ActivityRecord`] structure plus the key in the [`HashMap`] takes less
/// than 100 bytes, so this should allocate around a megabyte of memory.
static MAX_PENDING_RECORDS: usize = 10_000;

const TYPE: Key = Key::from_static_str("type");
const SESSION_KIND: Key = Key::from_static_str("session_kind");
const RESULT: Key = Key::from_static_str("result");

#[derive(Clone, Copy, Debug)]
struct ActivityRecord {
    // XXX: We don't actually use the start time for now
    #[allow(dead_code)]
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    ip: Option<IpAddr>,
}

/// Handles writing activity records to the database.
pub struct Worker {
    pool: PgPool,
    pending_records: HashMap<(SessionKind, Ulid), ActivityRecord>,
    message_counter: Counter<u64>,
    flush_time_histogram: Histogram<u64>,
}

impl Worker {
    pub(crate) fn new(pool: PgPool) -> Self {
        let meter = opentelemetry::global::meter_with_version(
            env!("CARGO_PKG_NAME"),
            Some(env!("CARGO_PKG_VERSION")),
            Some(opentelemetry_semantic_conventions::SCHEMA_URL),
            None,
        );

        let message_counter = meter
            .u64_counter("mas.activity_tracker.messages")
            .with_description("The number of messages received by the activity tracker")
            .with_unit("{messages}")
            .init();

        // Record stuff on the counter so that the metrics are initialized
        for kind in &[
            SessionKind::OAuth2,
            SessionKind::Compat,
            SessionKind::Browser,
        ] {
            message_counter.add(
                0,
                &[TYPE.string("record"), SESSION_KIND.string(kind.as_str())],
            );
        }
        message_counter.add(0, &[TYPE.string("flush")]);
        message_counter.add(0, &[TYPE.string("shutdown")]);

        let flush_time_histogram = meter
            .u64_histogram("mas.activity_tracker.flush_time")
            .with_description("The time it took to flush the activity tracker")
            .with_unit("ms")
            .init();

        Self {
            pool,
            pending_records: HashMap::with_capacity(MAX_PENDING_RECORDS),
            message_counter,
            flush_time_histogram,
        }
    }

    pub(super) async fn run(mut self, mut receiver: tokio::sync::mpsc::Receiver<Message>) {
        let mut shutdown_notifier = None;
        while let Some(message) = receiver.recv().await {
            match message {
                Message::Record {
                    kind,
                    id,
                    date_time,
                    ip,
                } => {
                    if self.pending_records.len() >= MAX_PENDING_RECORDS {
                        tracing::warn!("Too many pending activity records, flushing");
                        self.flush().await;
                    }

                    if self.pending_records.len() >= MAX_PENDING_RECORDS {
                        tracing::error!(
                            kind = kind.as_str(),
                            %id,
                            %date_time,
                            "Still too many pending activity records, dropping"
                        );
                        continue;
                    }

                    self.message_counter.add(
                        1,
                        &[TYPE.string("record"), SESSION_KIND.string(kind.as_str())],
                    );

                    let record =
                        self.pending_records
                            .entry((kind, id))
                            .or_insert_with(|| ActivityRecord {
                                start_time: date_time,
                                end_time: date_time,
                                ip,
                            });

                    record.end_time = date_time.max(record.end_time);
                }
                Message::Flush(tx) => {
                    self.message_counter.add(1, &[TYPE.string("flush")]);

                    self.flush().await;
                    let _ = tx.send(());
                }
                Message::Shutdown(tx) => {
                    self.message_counter.add(1, &[TYPE.string("shutdown")]);

                    let old_tx = shutdown_notifier.replace(tx);
                    if let Some(old_tx) = old_tx {
                        tracing::warn!("Activity tracker shutdown requested while another shutdown was already in progress");
                        // Still send the shutdown signal to the previous notifier. This means we
                        // send the shutdown signal before we flush the activity tracker, but that
                        // should be fine, since there should not be multiple shutdown requests.
                        let _ = old_tx.send(());
                    }
                    receiver.close();
                }
            }
        }

        self.flush().await;

        if let Some(shutdown_notifier) = shutdown_notifier {
            let _ = shutdown_notifier.send(());
        } else {
            // This should never happen, since we set the shutdown notifier when we receive
            // the first shutdown message
            tracing::warn!("Activity tracker shutdown requested but no shutdown notifier was set");
        }
    }

    /// Flush the activity tracker.
    async fn flush(&mut self) {
        // Short path: if there are no pending records, we don't need to flush
        if self.pending_records.is_empty() {
            return;
        }

        let start = std::time::Instant::now();
        let res = self.try_flush().await;

        // Measure the time it took to flush the activity tracker
        let duration = start.elapsed();
        let duration_ms = duration.as_millis().try_into().unwrap_or(u64::MAX);

        match res {
            Ok(()) => {
                self.flush_time_histogram
                    .record(duration_ms, &[RESULT.string("success")]);
            }
            Err(e) => {
                self.flush_time_histogram
                    .record(duration_ms, &[RESULT.string("failure")]);
                tracing::error!("Failed to flush activity tracker: {}", e);
            }
        }
    }

    /// Fallible part of [`Self::flush`].
    #[tracing::instrument(name = "activity_tracker.flush", skip(self))]
    async fn try_flush(&mut self) -> Result<(), anyhow::Error> {
        let pending_records = &self.pending_records;

        let mut repo = mas_storage_pg::PgRepository::from_pool(&self.pool)
            .await?
            .boxed();

        let mut browser_sessions = Vec::new();
        let mut oauth2_sessions = Vec::new();
        let mut compat_sessions = Vec::new();

        for ((kind, id), record) in pending_records {
            match kind {
                SessionKind::Browser => {
                    browser_sessions.push((*id, record.end_time, record.ip));
                }
                SessionKind::OAuth2 => {
                    oauth2_sessions.push((*id, record.end_time, record.ip));
                }
                SessionKind::Compat => {
                    compat_sessions.push((*id, record.end_time, record.ip));
                }
            }
        }

        tracing::info!(
            "Flushing {} activity records to the database",
            pending_records.len()
        );

        repo.browser_session()
            .record_batch_activity(browser_sessions)
            .await?;
        repo.oauth2_session()
            .record_batch_activity(oauth2_sessions)
            .await?;
        repo.compat_session()
            .record_batch_activity(compat_sessions)
            .await?;

        repo.save().await?;
        self.pending_records.clear();

        Ok(())
    }
}
