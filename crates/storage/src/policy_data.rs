// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Repositories to interact with the policy data saved in the storage backend.

use async_trait::async_trait;
use mas_data_model::{Clock, PolicyData};
use rand_core::RngCore;

use crate::repository_impl;

/// A [`PolicyDataRepository`] helps interacting with the policy data saved in
/// the storage backend.
#[async_trait]
pub trait PolicyDataRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Get the latest policy data
    ///
    /// Returns the latest policy data, or `None` if no policy data is
    /// available.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn get(&mut self) -> Result<Option<PolicyData>, Self::Error>;

    /// Set the latest policy data
    ///
    /// Returns the newly created policy data.
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate the timestamps
    /// * `data`: The policy data to set
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn set(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        data: serde_json::Value,
    ) -> Result<PolicyData, Self::Error>;

    /// Prune old policy data
    ///
    /// Returns the number of entries pruned.
    ///
    /// # Parameters
    ///
    /// * `keep`: the number of old entries to keep
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn prune(&mut self, keep: usize) -> Result<usize, Self::Error>;
}

repository_impl!(PolicyDataRepository:
    async fn get(&mut self) -> Result<Option<PolicyData>, Self::Error>;

    async fn set(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        data: serde_json::Value,
    ) -> Result<PolicyData, Self::Error>;

    async fn prune(&mut self, keep: usize) -> Result<usize, Self::Error>;
);
