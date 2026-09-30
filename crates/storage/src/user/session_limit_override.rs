// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::num::NonZeroU64;

use async_trait::async_trait;
use mas_data_model::{Client, Clock, User, UserSessionLimitOverride};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Page, Pagination, repository_impl};

/// Filter parameters for listing [`UserSessionLimitOverride`]s
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct UserSessionLimitOverrideFilter<'a> {
    user: Option<&'a User>,
    client: Option<&'a Client>,
    global_only: Option<bool>,
}

impl<'a> UserSessionLimitOverrideFilter<'a> {
    /// Create a new empty filter
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter for overrides of a specific user
    #[must_use]
    pub fn for_user(mut self, user: &'a User) -> Self {
        self.user = Some(user);
        self
    }

    /// Get the user filter
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.user
    }

    /// Filter for overrides of a specific OAuth 2.0 client
    #[must_use]
    pub fn for_client(mut self, client: &'a Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Get the client filter
    #[must_use]
    pub fn client(&self) -> Option<&Client> {
        self.client
    }

    /// Filter for global overrides (`oauth2_client_id` is NULL)
    #[must_use]
    pub fn global_only(mut self) -> Self {
        self.global_only = Some(true);
        self
    }

    /// Whether only global overrides should be returned
    #[must_use]
    pub fn is_global_only(&self) -> bool {
        self.global_only == Some(true)
    }
}

/// A [`UserSessionLimitOverrideRepository`] helps interacting with
/// [`UserSessionLimitOverride`] rows
#[async_trait]
pub trait UserSessionLimitOverrideRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`UserSessionLimitOverride`] by its ID
    ///
    /// Returns `None` if no row was found
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserSessionLimitOverride>, Self::Error>;

    /// Lookup a [`UserSessionLimitOverride`] for a user and optional client
    ///
    /// Pass `client_id = None` for the global override.
    async fn find(
        &mut self,
        user: &User,
        client_id: Option<Ulid>,
    ) -> Result<Option<UserSessionLimitOverride>, Self::Error>;

    /// List [`UserSessionLimitOverride`]s matching the given filter
    async fn list(
        &mut self,
        filter: UserSessionLimitOverrideFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserSessionLimitOverride>, Self::Error>;

    /// Count [`UserSessionLimitOverride`]s matching the given filter
    async fn count(
        &mut self,
        filter: UserSessionLimitOverrideFilter<'_>,
    ) -> Result<usize, Self::Error>;

    /// Create a new [`UserSessionLimitOverride`]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        client_id: Option<Ulid>,
        soft_limit: NonZeroU64,
        hard_limit: NonZeroU64,
    ) -> Result<UserSessionLimitOverride, Self::Error>;

    /// Update the soft and hard limits of a [`UserSessionLimitOverride`]
    async fn set_limits(
        &mut self,
        clock: &dyn Clock,
        override_row: UserSessionLimitOverride,
        soft_limit: NonZeroU64,
        hard_limit: NonZeroU64,
    ) -> Result<UserSessionLimitOverride, Self::Error>;

    /// Delete a [`UserSessionLimitOverride`]
    async fn remove(&mut self, override_row: UserSessionLimitOverride) -> Result<(), Self::Error>;
}

repository_impl!(UserSessionLimitOverrideRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserSessionLimitOverride>, Self::Error>;
    async fn find(
        &mut self,
        user: &User,
        client_id: Option<Ulid>,
    ) -> Result<Option<UserSessionLimitOverride>, Self::Error>;
    async fn list(
        &mut self,
        filter: UserSessionLimitOverrideFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserSessionLimitOverride>, Self::Error>;
    async fn count(
        &mut self,
        filter: UserSessionLimitOverrideFilter<'_>,
    ) -> Result<usize, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        client_id: Option<Ulid>,
        soft_limit: NonZeroU64,
        hard_limit: NonZeroU64,
    ) -> Result<UserSessionLimitOverride, Self::Error>;
    async fn set_limits(
        &mut self,
        clock: &dyn Clock,
        override_row: UserSessionLimitOverride,
        soft_limit: NonZeroU64,
        hard_limit: NonZeroU64,
    ) -> Result<UserSessionLimitOverride, Self::Error>;
    async fn remove(
        &mut self,
        override_row: UserSessionLimitOverride,
    ) -> Result<(), Self::Error>;
);
