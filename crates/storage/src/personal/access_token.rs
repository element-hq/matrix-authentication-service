// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::Duration;
use mas_data_model::{
    Clock,
    personal::{PersonalAccessToken, session::PersonalSession},
};
use rand_core::RngCore;
use ulid::Ulid;

use crate::repository_impl;

/// An [`PersonalAccessTokenRepository`] helps interacting with
/// [`PersonalAccessToken`] saved in the storage backend
#[async_trait]
pub trait PersonalAccessTokenRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an access token by its ID
    ///
    /// Returns the access token if it exists, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the access token to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalAccessToken>, Self::Error>;

    /// Find an access token by its token
    ///
    /// Returns the access token if it exists, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `access_token`: The token of the access token to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<PersonalAccessToken>, Self::Error>;

    /// Add a new access token to the database
    ///
    /// Returns the newly created access token
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator
    /// * `clock`: The clock used to generate timestamps
    /// * `session`: The session the access token is associated with
    /// * `access_token`: The access token to add
    /// * `expires_after`: The duration after which the access token expires. If
    ///   [`None`] the access token never expires
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &PersonalSession,
        access_token: &str,
        expires_after: Option<Duration>,
    ) -> Result<PersonalAccessToken, Self::Error>;

    /// Revoke an access token
    ///
    /// Returns the revoked access token
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `access_token`: The access token to revoke
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        access_token: PersonalAccessToken,
    ) -> Result<PersonalAccessToken, Self::Error>;
}

repository_impl!(PersonalAccessTokenRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalAccessToken>, Self::Error>;

    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<PersonalAccessToken>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &PersonalSession,
        access_token: &str,
        expires_after: Option<Duration>,
    ) -> Result<PersonalAccessToken, Self::Error>;

    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        access_token: PersonalAccessToken,
    ) -> Result<PersonalAccessToken, Self::Error>;
);
