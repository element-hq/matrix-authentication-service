// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! # MAS Database Checks
//!
//! This module provides safety checks to run against a MAS database before
//! running the Synapse-to-MAS migration.

use thiserror::Error;
use thiserror_ext::ContextInto;

use super::{is_syn2mas_in_progress, locking::LockedMasDatabase, MAS_TABLES_AFFECTED_BY_MIGRATION};

#[derive(Debug, Error, ContextInto)]
pub enum Error {
    #[error("the MAS database is not empty: rows found in at least `{table}`")]
    MasDatabaseNotEmpty { table: &'static str },

    #[error("query against {table} failed — is this actually a MAS database?")]
    MaybeNotMas {
        #[source]
        source: sqlx::Error,
        table: &'static str,
    },

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error("unable to check if syn2mas is already in progress")]
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
#[tracing::instrument(skip_all)]
pub async fn mas_pre_migration_checks<'a>(
    mas_connection: &mut LockedMasDatabase<'a>,
) -> Result<(), Error> {
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
        let row_present = sqlx::query(&format!("SELECT 1 AS dummy FROM {table} LIMIT 1"))
            .fetch_optional(mas_connection.as_mut())
            .await
            .into_maybe_not_mas(table)?
            .is_some();

        if row_present {
            return Err(Error::MasDatabaseNotEmpty { table });
        }
    }

    Ok(())
}
