// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{AccessToken, RefreshToken, Session};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, repository_impl};

/// An [`OAuth2RefreshTokenRepository`] helps interacting with [`RefreshToken`]
/// saved in the storage backend
#[async_trait]
pub trait OAuth2RefreshTokenRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a refresh token by its ID
    ///
    /// Returns `None` if no [`RefreshToken`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`RefreshToken`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<RefreshToken>, Self::Error>;

    /// Find a refresh token by its token
    ///
    /// Returns `None` if no [`RefreshToken`] was found
    ///
    /// # Parameters
    ///
    /// * `token`: The token of the [`RefreshToken`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, Self::Error>;

    /// Add a new refresh token to the database
    ///
    /// Returns the newly created [`RefreshToken`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `session`: The [`Session`] in which to create the [`RefreshToken`]
    /// * `access_token`: The [`AccessToken`] created alongside this
    ///   [`RefreshToken`]
    /// * `refresh_token`: The refresh token to store
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: &AccessToken,
        refresh_token: String,
    ) -> Result<RefreshToken, Self::Error>;

    /// Consume a refresh token
    ///
    /// Returns the updated [`RefreshToken`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `refresh_token`: The [`RefreshToken`] to consume
    /// * `replaced_by`: The [`RefreshToken`] which replaced this one
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails, or if the
    /// token was already consumed or revoked
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
        replaced_by: &RefreshToken,
    ) -> Result<RefreshToken, Self::Error>;

    /// Revoke a refresh token
    ///
    /// Returns the updated [`RefreshToken`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `refresh_token`: The [`RefreshToken`] to revoke
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails, or if the
    /// token was already revoked or consumed
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
    ) -> Result<RefreshToken, Self::Error>;
}

repository_impl!(OAuth2RefreshTokenRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<RefreshToken>, Self::Error>;

    async fn find_by_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: &AccessToken,
        refresh_token: String,
    ) -> Result<RefreshToken, Self::Error>;

    async fn consume(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
        replaced_by: &RefreshToken,
    ) -> Result<RefreshToken, Self::Error>;

    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        refresh_token: RefreshToken,
    ) -> Result<RefreshToken, Self::Error>;
);
