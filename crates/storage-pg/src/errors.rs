// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use sqlx::postgres::PgQueryResult;
use thiserror::Error;
use ulid::Ulid;

/// Generic error when interacting with the database
#[derive(Debug, Error)]
#[error(transparent)]
pub enum DatabaseError {
    /// An error which came from the database itself
    Driver {
        /// The underlying error from the database driver
        #[from]
        source: sqlx::Error,
    },

    /// An error which occured while converting the data from the database
    Inconsistency(#[from] DatabaseInconsistencyError),

    /// An error which happened because the requested database operation is
    /// invalid
    #[error("Invalid database operation")]
    InvalidOperation {
        /// The source of the error, if any
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// An error which happens when an operation affects not enough or too many
    /// rows
    #[error("Expected {expected} rows to be affected, but {actual} rows were affected")]
    RowsAffected {
        /// How many rows were expected to be affected
        expected: u64,

        /// How many rows were actually affected
        actual: u64,
    },
}

impl DatabaseError {
    pub(crate) fn ensure_affected_rows(
        result: &PgQueryResult,
        expected: u64,
    ) -> Result<(), DatabaseError> {
        let actual = result.rows_affected();
        if actual == expected {
            Ok(())
        } else {
            Err(DatabaseError::RowsAffected { expected, actual })
        }
    }

    pub(crate) fn to_invalid_operation<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::InvalidOperation {
            source: Some(Box::new(e)),
        }
    }

    pub(crate) const fn invalid_operation() -> Self {
        Self::InvalidOperation { source: None }
    }
}

/// An error which occured while converting the data from the database
#[derive(Debug, Error)]
pub struct DatabaseInconsistencyError {
    /// The table which was being queried
    table: &'static str,

    /// The column which was being queried
    column: Option<&'static str>,

    /// The row which was being queried
    row: Option<Ulid>,

    /// The source of the error
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl std::fmt::Display for DatabaseInconsistencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Database inconsistency on table {}", self.table)?;
        if let Some(column) = self.column {
            write!(f, " column {column}")?;
        }
        if let Some(row) = self.row {
            write!(f, " row {row}")?;
        }

        Ok(())
    }
}

impl DatabaseInconsistencyError {
    /// Create a new [`DatabaseInconsistencyError`] for the given table
    #[must_use]
    pub(crate) const fn on(table: &'static str) -> Self {
        Self {
            table,
            column: None,
            row: None,
            source: None,
        }
    }

    /// Set the column which was being queried
    #[must_use]
    pub(crate) const fn column(mut self, column: &'static str) -> Self {
        self.column = Some(column);
        self
    }

    /// Set the row which was being queried
    #[must_use]
    pub(crate) const fn row(mut self, row: Ulid) -> Self {
        self.row = Some(row);
        self
    }

    /// Give the source of the error
    #[must_use]
    pub(crate) fn source<E: std::error::Error + Send + Sync + 'static>(
        mut self,
        source: E,
    ) -> Self {
        self.source = Some(Box::new(source));
        self
    }
}
