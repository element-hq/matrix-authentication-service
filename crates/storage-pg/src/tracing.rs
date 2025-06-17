// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use opentelemetry_semantic_conventions::attribute::DB_QUERY_TEXT;
use tracing::Span;

/// An extension trait for [`sqlx::Execute`] that records the SQL statement as
/// `db.query.text` in a tracing span
pub trait ExecuteExt<'q, DB>: Sized {
    /// Records the statement as `db.query.text` in the current span
    #[must_use]
    fn traced(self) -> Self {
        self.record(&Span::current())
    }

    /// Records the statement as `db.query.text` in the given span
    #[must_use]
    fn record(self, span: &Span) -> Self;
}

impl<'q, DB, T> ExecuteExt<'q, DB> for T
where
    T: sqlx::Execute<'q, DB>,
    DB: sqlx::Database,
{
    fn record(self, span: &Span) -> Self {
        span.record(DB_QUERY_TEXT, self.sql());
        self
    }
}
