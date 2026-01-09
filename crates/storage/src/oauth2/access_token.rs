// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{AccessToken, Clock, Session};
use rand_core::RngCore;
use ulid::Ulid;

use crate::repository_impl;

/// An [`OAuth2AccessTokenRepository`] helps interacting with [`AccessToken`]
/// saved in the storage backend
#[async_trait]
pub trait OAuth2AccessTokenRepository: Send + Sync {
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
    async fn lookup(&mut self, id: Ulid) -> Result<Option<AccessToken>, Self::Error>;

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
    ) -> Result<Option<AccessToken>, Self::Error>;

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
        session: &Session,
        access_token: String,
        expires_after: Option<Duration>,
    ) -> Result<AccessToken, Self::Error>;

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
        access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error>;

    /// Mark the access token as used, to track when it was first used
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `access_token`: The access token to mark as used
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn mark_used(
        &mut self,
        clock: &dyn Clock,
        access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error>;

    /// Cleanup revoked access tokens
    ///
    /// Returns the number of access tokens that were cleaned up, as well as the
    /// timestamp of the last access token revoked
    ///
    /// # Parameters
    ///
    /// * `since`: An optional datetime since which to clean up revoked access
    ///   tokens. This is useful to call this method multiple times in a row
    /// * `until`: The datetime until which to clean up revoked access tokens
    /// * `limit`: The maximum number of access tokens to clean up
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn cleanup_revoked(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error>;

    /// Cleanup expired access tokens
    ///
    /// Returns the number of access tokens that were cleaned up, as well as the
    /// timestamp of the last access token expiration
    ///
    /// # Parameters
    ///
    /// * `since`: An optional datetime since which to clean up expired access
    ///   tokens. This is useful to call this method multiple times in a row
    /// * `until`: The datetime until which to clean up expired access tokens
    /// * `limit`: The maximum number of access tokens to clean up
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn cleanup_expired(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error>;
}

repository_impl!(OAuth2AccessTokenRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<AccessToken>, Self::Error>;

    async fn find_by_token(
        &mut self,
        access_token: &str,
    ) -> Result<Option<AccessToken>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        session: &Session,
        access_token: String,
        expires_after: Option<Duration>,
    ) -> Result<AccessToken, Self::Error>;

    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error>;

    async fn mark_used(
        &mut self,
        clock: &dyn Clock,
        access_token: AccessToken,
    ) -> Result<AccessToken, Self::Error>;

    async fn cleanup_revoked(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error>;

    async fn cleanup_expired(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error>;
);
