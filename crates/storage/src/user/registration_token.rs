// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::UserRegistrationToken;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, repository_impl};

/// A filter to apply when listing [`UserRegistrationToken`]s
#[derive(Debug, Clone, Copy)]
pub struct UserRegistrationTokenFilter {
    now: DateTime<Utc>,
    has_been_used: Option<bool>,
    is_revoked: Option<bool>,
    is_expired: Option<bool>,
    is_valid: Option<bool>,
}

impl UserRegistrationTokenFilter {
    /// Create a new empty filter
    #[must_use]
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            now,
            has_been_used: None,
            is_revoked: None,
            is_expired: None,
            is_valid: None,
        }
    }

    /// Filter by whether the token has been used at least once
    #[must_use]
    pub fn with_been_used(mut self, has_been_used: bool) -> Self {
        self.has_been_used = Some(has_been_used);
        self
    }

    /// Filter by revoked status
    #[must_use]
    pub fn with_revoked(mut self, is_revoked: bool) -> Self {
        self.is_revoked = Some(is_revoked);
        self
    }

    /// Filter by expired status
    #[must_use]
    pub fn with_expired(mut self, is_expired: bool) -> Self {
        self.is_expired = Some(is_expired);
        self
    }

    /// Filter by valid status (meaning: not expired, not revoked, and still
    /// with uses left)
    #[must_use]
    pub fn with_valid(mut self, is_valid: bool) -> Self {
        self.is_valid = Some(is_valid);
        self
    }

    /// Get the used status filter
    ///
    /// Returns [`None`] if no used status filter was set
    #[must_use]
    pub fn has_been_used(&self) -> Option<bool> {
        self.has_been_used
    }

    /// Get the revoked status filter
    ///
    /// Returns [`None`] if no revoked status filter was set
    #[must_use]
    pub fn is_revoked(&self) -> Option<bool> {
        self.is_revoked
    }

    /// Get the expired status filter
    ///
    /// Returns [`None`] if no expired status filter was set
    #[must_use]
    pub fn is_expired(&self) -> Option<bool> {
        self.is_expired
    }

    /// Get the valid status filter
    ///
    /// Returns [`None`] if no valid status filter was set
    #[must_use]
    pub fn is_valid(&self) -> Option<bool> {
        self.is_valid
    }

    /// Get the current time for this filter evaluation
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        self.now
    }
}

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

    /// Unrevoke a previously revoked [`UserRegistrationToken`]
    ///
    /// # Parameters
    ///
    /// * `token`: The [`UserRegistrationToken`] to unrevoke
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn unrevoke(
        &mut self,
        token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error>;

    /// Set the expiration time of a [`UserRegistrationToken`]
    ///
    /// # Parameters
    ///
    /// * `token`: The [`UserRegistrationToken`] to update
    /// * `expires_at`: The new expiration time, or `None` to remove the
    ///   expiration
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn set_expiry(
        &mut self,
        token: UserRegistrationToken,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UserRegistrationToken, Self::Error>;

    /// Set the usage limit of a [`UserRegistrationToken`]
    ///
    /// # Parameters
    ///
    /// * `token`: The [`UserRegistrationToken`] to update
    /// * `usage_limit`: The new usage limit, or `None` to remove the limit
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn set_usage_limit(
        &mut self,
        token: UserRegistrationToken,
        usage_limit: Option<u32>,
    ) -> Result<UserRegistrationToken, Self::Error>;

    /// List [`UserRegistrationToken`]s based on the provided filter
    ///
    /// Returns a list of matching [`UserRegistrationToken`]s
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    /// * `pagination`: The pagination parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list(
        &mut self,
        filter: UserRegistrationTokenFilter,
        pagination: crate::Pagination,
    ) -> Result<crate::Page<UserRegistrationToken>, Self::Error>;

    /// Count [`UserRegistrationToken`]s based on the provided filter
    ///
    /// Returns the number of matching [`UserRegistrationToken`]s
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: UserRegistrationTokenFilter) -> Result<usize, Self::Error>;
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
    async fn unrevoke(
        &mut self,
        token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error>;
    async fn set_expiry(
        &mut self,
        token: UserRegistrationToken,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UserRegistrationToken, Self::Error>;
    async fn set_usage_limit(
        &mut self,
        token: UserRegistrationToken,
        usage_limit: Option<u32>,
    ) -> Result<UserRegistrationToken, Self::Error>;
    async fn list(
        &mut self,
        filter: UserRegistrationTokenFilter,
        pagination: crate::Pagination,
    ) -> Result<crate::Page<UserRegistrationToken>, Self::Error>;
    async fn count(&mut self, filter: UserRegistrationTokenFilter) -> Result<usize, Self::Error>;
);
