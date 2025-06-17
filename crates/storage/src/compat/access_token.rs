// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::Duration;
use mas_data_model::{CompatAccessToken, CompatSession};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, repository_impl};

/// A [`CompatAccessTokenRepository`] helps interacting with
/// [`CompatAccessToken`] saved in the storage backend
#[async_trait]
pub trait CompatAccessTokenRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a compat access token by its ID
    ///
    /// Returns the compat access token if it exists, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the compat access token to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatAccessToken>, Self::Error>;

    /// Find a compat access token by its token
    ///
    /// Returns the compat access token if found, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `access_token`: The token of the compat access token to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<CompatAccessToken>, Self::Error>;

    /// Add a new compat access token to the database
    ///
    /// Returns the newly created compat access token
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `compat_session`: The compat session associated with the access token
    /// * `token`: The token of the access token
    /// * `expires_after`: The duration after which the access token expires, if
    ///   specified
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        compat_session: &CompatSession,
        token: String,
        expires_after: Option<Duration>,
    ) -> Result<CompatAccessToken, Self::Error>;

    /// Set the expiration time of the compat access token to now
    ///
    /// Returns the expired compat access token
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `compat_access_token`: The compat access token to expire
    async fn expire(
        &mut self,
        clock: &dyn Clock,
        compat_access_token: CompatAccessToken,
    ) -> Result<CompatAccessToken, Self::Error>;
}

repository_impl!(CompatAccessTokenRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<CompatAccessToken>, Self::Error>;

    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<CompatAccessToken>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        compat_session: &CompatSession,
        token: String,
        expires_after: Option<Duration>,
    ) -> Result<CompatAccessToken, Self::Error>;

    async fn expire(
        &mut self,
        clock: &dyn Clock,
        compat_access_token: CompatAccessToken,
    ) -> Result<CompatAccessToken, Self::Error>;
);
