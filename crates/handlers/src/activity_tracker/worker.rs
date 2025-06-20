// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashMap, net::IpAddr};

use chrono::{DateTime, Utc};
use mas_storage::{
    BoxRepositoryFactory, RepositoryAccess, RepositoryError, user::BrowserSessionRepository,
};
use opentelemetry::{
    Key, KeyValue,
    metrics::{Counter, Gauge, Histogram},
};
use tokio_util::sync::CancellationToken;
use ulid::Ulid;

use crate::{
    METER,
    activity_tracker::{Message, SessionKind},
};

/// The maximum number of pending activity records before we flush them to the
/// database automatically.
///
/// The [`ActivityRecord`] structure plus the key in the [`HashMap`] takes less
/// than 100 bytes, so this should allocate around 100kB of memory.
static MAX_PENDING_RECORDS: usize = 1000;

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
    repository_factory: BoxRepositoryFactory,
    pending_records: HashMap<(SessionKind, Ulid), ActivityRecord>,
    pending_records_gauge: Gauge<u64>,
    message_counter: Counter<u64>,
    flush_time_histogram: Histogram<u64>,
}

impl Worker {
    pub(crate) fn new(repository_factory: BoxRepositoryFactory) -> Self {
        let message_counter = METER
            .u64_counter("mas.activity_tracker.messages")
            .with_description("The number of messages received by the activity tracker")
            .with_unit("{messages}")
            .build();

        // Record stuff on the counter so that the metrics are initialized
        for kind in &[
            SessionKind::OAuth2,
            SessionKind::Compat,
            SessionKind::Browser,
        ] {
            message_counter.add(
                0,
                &[
                    KeyValue::new(TYPE, "record"),
                    KeyValue::new(SESSION_KIND, kind.as_str()),
                ],
            );
        }
        message_counter.add(0, &[KeyValue::new(TYPE, "flush")]);
        message_counter.add(0, &[KeyValue::new(TYPE, "shutdown")]);

        let flush_time_histogram = METER
            .u64_histogram("mas.activity_tracker.flush_time")
            .with_description("The time it took to flush the activity tracker")
            .with_unit("ms")
            .build();

        let pending_records_gauge = METER
            .u64_gauge("mas.activity_tracker.pending_records")
            .with_description("The number of pending activity records")
            .with_unit("{records}")
            .build();
        pending_records_gauge.record(0, &[]);

        Self {
            repository_factory,
            pending_records: HashMap::with_capacity(MAX_PENDING_RECORDS),
            pending_records_gauge,
            message_counter,
            flush_time_histogram,
        }
    }

    pub(super) async fn run(
        mut self,
        mut receiver: tokio::sync::mpsc::Receiver<Message>,
        cancellation_token: CancellationToken,
    ) {
        // This guard on the shutdown token is to ensure that if this task crashes for
        // any reason, the server will shut down
        let _guard = cancellation_token.clone().drop_guard();

        loop {
            let message = tokio::select! {
                // Because we want the cancellation token to trigger only once,
                // we looked whether we closed the channel or not
                () = cancellation_token.cancelled(), if !receiver.is_closed() => {
                    // We only close the channel, which will make it flush all
                    // the pending messages
                    receiver.close();
                    tracing::debug!("Shutting down activity tracker");
                    continue;
                },

                message = receiver.recv()  => {
                    // We consumed all the messages, break out of the loop
                    let Some(message) = message else { break };
                    message
                }
            };

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
                        &[
                            KeyValue::new(TYPE, "record"),
                            KeyValue::new(SESSION_KIND, kind.as_str()),
                        ],
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
                    self.message_counter.add(1, &[KeyValue::new(TYPE, "flush")]);

                    self.flush().await;
                    let _ = tx.send(());
                }
            }

            // Update the gauge
            self.pending_records_gauge
                .record(self.pending_records.len() as u64, &[]);
        }

        // Flush one last time
        self.flush().await;
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
                    .record(duration_ms, &[KeyValue::new(RESULT, "success")]);
            }
            Err(e) => {
                self.flush_time_histogram
                    .record(duration_ms, &[KeyValue::new(RESULT, "failure")]);
                tracing::error!(
                    error = &e as &dyn std::error::Error,
                    "Failed to flush activity tracker"
                );
            }
        }
    }

    /// Fallible part of [`Self::flush`].
    #[tracing::instrument(name = "activity_tracker.flush", skip(self))]
    async fn try_flush(&mut self) -> Result<(), RepositoryError> {
        let pending_records = &self.pending_records;
        let mut repo = self.repository_factory.create().await?;

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
