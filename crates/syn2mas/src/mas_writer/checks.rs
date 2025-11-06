// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! # MAS Database Checks
//!
//! This module provides safety checks to run against a MAS database before
//! running the Synapse-to-MAS migration.

use thiserror::Error;
use thiserror_ext::ContextInto;
use tracing::Instrument as _;

use super::{MAS_TABLES_AFFECTED_BY_MIGRATION, is_syn2mas_in_progress, locking::LockedMasDatabase};

#[derive(Debug, Error, ContextInto)]
pub enum Error {
    #[error(
        "The MAS database is not empty: rows found in at least `{table}`. Please drop and recreate the database, then try again."
    )]
    MasDatabaseNotEmpty { table: &'static str },

    #[error("Query against {table} failed — is this actually a MAS database?")]
    MaybeNotMas {
        #[source]
        source: sqlx::Error,
        table: &'static str,
    },

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error("Unable to check if syn2mas is already in progress")]
    UnableToCheckInProgress(#[source] super::Error),
}

/// Check that a MAS database is ready for being migrated to.
///
/// Concretely, this checks that the database is empty.
///
/// If syn2mas is already in progress on this database, the checks are skipped.
///
/// # Errors
///
/// Errors are returned under the following circumstances:
///
/// - If any database access error occurs.
/// - If any MAS tables involved in the migration are not empty.
/// - If we can't check whether syn2mas is already in progress on this database
///   or not.
#[tracing::instrument(name = "syn2mas.mas_pre_migration_checks", skip_all)]
pub async fn mas_pre_migration_checks(mas_connection: &mut LockedMasDatabase) -> Result<(), Error> {
    if is_syn2mas_in_progress(mas_connection.as_mut())
        .await
        .map_err(Error::UnableToCheckInProgress)?
    {
        // syn2mas already in progress, so we already performed the checks
        return Ok(());
    }

    // Check that the database looks like a MAS database and that it is also an
    // empty database.

    for &table in MAS_TABLES_AFFECTED_BY_MIGRATION {
        let query = format!("SELECT 1 AS dummy FROM {table} LIMIT 1");
        let span = tracing::info_span!("db.query", db.query.text = query);
        let row_present = sqlx::query(&query)
            .fetch_optional(mas_connection.as_mut())
            .instrument(span)
            .await
            .into_maybe_not_mas(table)?
            .is_some();

        if row_present {
            return Err(Error::MasDatabaseNotEmpty { table });
        }
    }

    Ok(())
}
