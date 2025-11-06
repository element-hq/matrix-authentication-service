// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{Clock, Password, User};
use rand_core::RngCore;

use crate::repository_impl;

/// A [`UserPasswordRepository`] helps interacting with [`Password`] saved in
/// the storage backend
#[async_trait]
pub trait UserPasswordRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Get the active password for a user
    ///
    /// Returns `None` if the user has no password set
    ///
    /// # Parameters
    ///
    /// * `user`: The user to get the password for
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if underlying repository fails
    async fn active(&mut self, user: &User) -> Result<Option<Password>, Self::Error>;

    /// Set a new password for a user
    ///
    /// Returns the newly created [`Password`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The user to set the password for
    /// * `version`: The version of the hashing scheme used
    /// * `hashed_password`: The hashed password
    /// * `upgraded_from`: The password this password was upgraded from, if any
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        version: u16,
        hashed_password: String,
        upgraded_from: Option<&Password>,
    ) -> Result<Password, Self::Error>;
}

repository_impl!(UserPasswordRepository:
    async fn active(&mut self, user: &User) -> Result<Option<Password>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        version: u16,
        hashed_password: String,
        upgraded_from: Option<&Password>,
    ) -> Result<Password, Self::Error>;
);
