// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::LazyLock;

use sqlx::{
    Either, PgConnection,
    postgres::{PgAdvisoryLock, PgAdvisoryLockGuard},
};

static SYN2MAS_ADVISORY_LOCK: LazyLock<PgAdvisoryLock> =
    LazyLock::new(|| PgAdvisoryLock::new("syn2mas-maswriter"));

/// A wrapper around a Postgres connection which holds a session-wide advisory
/// lock preventing concurrent access by other syn2mas instances.
pub struct LockedMasDatabase {
    inner: PgAdvisoryLockGuard<'static, PgConnection>,
}

impl LockedMasDatabase {
    /// Attempts to lock the MAS database against concurrent access by other
    /// syn2mas instances.
    ///
    /// If the lock can be acquired, returns a `LockedMasDatabase`.
    /// If the lock cannot be acquired, returns the connection back to the
    /// caller wrapped in `Either::Right`.
    ///
    /// # Errors
    ///
    /// Errors are returned for underlying database errors.
    pub async fn try_new(
        mas_connection: PgConnection,
    ) -> Result<Either<Self, PgConnection>, sqlx::Error> {
        SYN2MAS_ADVISORY_LOCK
            .try_acquire(mas_connection)
            .await
            .map(|either| match either {
                Either::Left(inner) => Either::Left(LockedMasDatabase { inner }),
                Either::Right(unlocked) => Either::Right(unlocked),
            })
    }

    /// Releases the advisory lock on the MAS database, returning the underlying
    /// connection.
    ///
    /// # Errors
    ///
    /// Errors are returned for underlying database errors.
    pub async fn unlock(self) -> Result<PgConnection, sqlx::Error> {
        self.inner.release_now().await
    }
}

impl AsMut<PgConnection> for LockedMasDatabase {
    fn as_mut(&mut self) -> &mut PgConnection {
        self.inner.as_mut()
    }
}
