// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::UserRegistrationToken;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, repository_impl};

/// A [`UserRegistrationTokenRepository`] helps interacting with
/// [`UserRegistrationToken`] saved in the storage backend
#[async_trait]
pub trait UserRegistrationTokenRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`UserRegistrationToken`] by its ID
    ///
    /// Returns `None` if no [`UserRegistrationToken`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserRegistrationToken`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserRegistrationToken>, Self::Error>;

    /// Lookup a [`UserRegistrationToken`] by its token string
    ///
    /// Returns `None` if no [`UserRegistrationToken`] was found
    ///
    /// # Parameters
    ///
    /// * `token`: The token string to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_token(
        &mut self,
        token: &str,
    ) -> Result<Option<UserRegistrationToken>, Self::Error>;

    /// Create a new [`UserRegistrationToken`]
    ///
    /// Returns the newly created [`UserRegistrationToken`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `token`: The token string
    /// * `usage_limit`: Optional limit on how many times the token can be used
    /// * `expires_at`: Optional expiration time for the token
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        token: String,
        usage_limit: Option<u32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UserRegistrationToken, Self::Error>;

    /// Increment the usage count of a [`UserRegistrationToken`]
    ///
    /// Returns the updated [`UserRegistrationToken`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `token`: The [`UserRegistrationToken`] to update
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn use_token(
        &mut self,
        clock: &dyn Clock,
        token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error>;

    /// Revoke a [`UserRegistrationToken`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `token`: The [`UserRegistrationToken`] to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error>;
}

repository_impl!(UserRegistrationTokenRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserRegistrationToken>, Self::Error>;
    async fn find_by_token(&mut self, token: &str) -> Result<Option<UserRegistrationToken>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        token: String,
        usage_limit: Option<u32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UserRegistrationToken, Self::Error>;
    async fn use_token(
        &mut self,
        clock: &dyn Clock,
        token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error>;
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error>;
);
