// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Repositories to interact with entities related to user accounts

use async_trait::async_trait;
use mas_data_model::{Clock, User};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Page, Pagination, repository_impl};

mod email;
mod password;
mod recovery;
mod registration;
mod registration_token;
mod session;
mod terms;

pub use self::{
    email::{UserEmailFilter, UserEmailRepository},
    password::UserPasswordRepository,
    recovery::UserRecoveryRepository,
    registration::UserRegistrationRepository,
    registration_token::{UserRegistrationTokenFilter, UserRegistrationTokenRepository},
    session::{BrowserSessionFilter, BrowserSessionRepository},
    terms::UserTermsRepository,
};

/// The state of a user account
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserState {
    /// The account is deactivated, it has the `deactivated_at` timestamp set
    Deactivated,

    /// The account is locked, it has the `locked_at` timestamp set
    Locked,

    /// The account is active
    Active,
}

impl UserState {
    /// Returns `true` if the user state is [`Locked`].
    ///
    /// [`Locked`]: UserState::Locked
    #[must_use]
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked)
    }

    /// Returns `true` if the user state is [`Deactivated`].
    ///
    /// [`Deactivated`]: UserState::Deactivated
    #[must_use]
    pub fn is_deactivated(&self) -> bool {
        matches!(self, Self::Deactivated)
    }

    /// Returns `true` if the user state is [`Active`].
    ///
    /// [`Active`]: UserState::Active
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Filter parameters for listing users
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct UserFilter<'a> {
    state: Option<UserState>,
    can_request_admin: Option<bool>,
    is_guest: Option<bool>,
    search: Option<&'a str>,
}

impl<'a> UserFilter<'a> {
    /// Create a new [`UserFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter for active users
    #[must_use]
    pub fn active_only(mut self) -> Self {
        self.state = Some(UserState::Active);
        self
    }

    /// Filter for locked users
    #[must_use]
    pub fn locked_only(mut self) -> Self {
        self.state = Some(UserState::Locked);
        self
    }

    /// Filter for deactivated users
    #[must_use]
    pub fn deactivated_only(mut self) -> Self {
        self.state = Some(UserState::Deactivated);
        self
    }

    /// Filter for users that can request admin privileges
    #[must_use]
    pub fn can_request_admin_only(mut self) -> Self {
        self.can_request_admin = Some(true);
        self
    }

    /// Filter for users that can't request admin privileges
    #[must_use]
    pub fn cannot_request_admin_only(mut self) -> Self {
        self.can_request_admin = Some(false);
        self
    }

    /// Filter for guest users
    #[must_use]
    pub fn guest_only(mut self) -> Self {
        self.is_guest = Some(true);
        self
    }

    /// Filter for non-guest users
    #[must_use]
    pub fn non_guest_only(mut self) -> Self {
        self.is_guest = Some(false);
        self
    }

    /// Filter for users that match the given search string
    #[must_use]
    pub fn matching_search(mut self, search: &'a str) -> Self {
        self.search = Some(search);
        self
    }

    /// Get the state filter
    ///
    /// Returns [`None`] if no state filter was set
    #[must_use]
    pub fn state(&self) -> Option<UserState> {
        self.state
    }

    /// Get the can request admin filter
    ///
    /// Returns [`None`] if no can request admin filter was set
    #[must_use]
    pub fn can_request_admin(&self) -> Option<bool> {
        self.can_request_admin
    }

    /// Get the is guest filter
    ///
    /// Returns [`None`] if no is guest filter was set
    #[must_use]
    pub fn is_guest(&self) -> Option<bool> {
        self.is_guest
    }

    /// Get the search filter
    ///
    /// Returns [`None`] if no search filter was set
    #[must_use]
    pub fn search(&self) -> Option<&'a str> {
        self.search
    }
}

/// A [`UserRepository`] helps interacting with [`User`] saved in the storage
/// backend
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`User`] by its ID
    ///
    /// Returns `None` if no [`User`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`User`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error>;

    /// Find a [`User`] by its username, in a case-insensitive manner
    ///
    /// Returns `None` if no [`User`] was found
    ///
    /// # Parameters
    ///
    /// * `username`: The username of the [`User`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_username(&mut self, username: &str) -> Result<Option<User>, Self::Error>;

    /// Create a new [`User`]
    ///
    /// Returns the newly created [`User`]
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator to generate the [`User`] ID
    /// * `clock`: The clock used to generate timestamps
    /// * `username`: The username of the [`User`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
    ) -> Result<User, Self::Error>;

    /// Check if a [`User`] exists
    ///
    /// Returns `true` if the [`User`] exists, `false` otherwise
    ///
    /// # Parameters
    ///
    /// * `username`: The username of the [`User`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn exists(&mut self, username: &str) -> Result<bool, Self::Error>;

    /// Lock a [`User`]
    ///
    /// Returns the locked [`User`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The [`User`] to lock
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lock(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error>;

    /// Unlock a [`User`]
    ///
    /// Returns the unlocked [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] to unlock
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn unlock(&mut self, user: User) -> Result<User, Self::Error>;

    /// Deactivate a [`User`]
    ///
    /// Returns the deactivated [`User`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The [`User`] to deactivate
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn deactivate(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error>;

    /// Reactivate a [`User`]
    ///
    /// Returns the reactivated [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] to reactivate
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn reactivate(&mut self, user: User) -> Result<User, Self::Error>;

    /// Delete all the unsupported third-party IDs of a [`User`].
    ///
    /// Those were imported by syn2mas and kept in case we wanted to support
    /// them later. They still need to be cleaned up when a user deactivate
    /// their account.
    ///
    /// Returns the number of deleted third-party IDs.
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] whose unsupported third-party IDs should be
    ///   deleted
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn delete_unsupported_threepids(&mut self, user: &User) -> Result<usize, Self::Error>;

    /// Set whether a [`User`] can request admin
    ///
    /// Returns the [`User`] with the new `can_request_admin` value
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] to update
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn set_can_request_admin(
        &mut self,
        user: User,
        can_request_admin: bool,
    ) -> Result<User, Self::Error>;

    /// List [`User`] with the given filter and pagination
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    /// * `pagination`: The pagination parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn list(
        &mut self,
        filter: UserFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<User>, Self::Error>;

    /// Count the [`User`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: UserFilter<'_>) -> Result<usize, Self::Error>;

    /// Acquire a lock on the user to make sure device operations are done in a
    /// sequential way. The lock is released when the repository is saved or
    /// rolled back.
    ///
    /// # Parameters
    ///
    /// * `user`: The user to lock
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn acquire_lock_for_sync(&mut self, user: &User) -> Result<(), Self::Error>;
}

repository_impl!(UserRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<User>, Self::Error>;
    async fn find_by_username(&mut self, username: &str) -> Result<Option<User>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
    ) -> Result<User, Self::Error>;
    async fn exists(&mut self, username: &str) -> Result<bool, Self::Error>;
    async fn lock(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error>;
    async fn unlock(&mut self, user: User) -> Result<User, Self::Error>;
    async fn deactivate(&mut self, clock: &dyn Clock, user: User) -> Result<User, Self::Error>;
    async fn reactivate(&mut self, user: User) -> Result<User, Self::Error>;
    async fn delete_unsupported_threepids(&mut self, user: &User) -> Result<usize, Self::Error>;
    async fn set_can_request_admin(
        &mut self,
        user: User,
        can_request_admin: bool,
    ) -> Result<User, Self::Error>;
    async fn list(
        &mut self,
        filter: UserFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<User>, Self::Error>;
    async fn count(&mut self, filter: UserFilter<'_>) -> Result<usize, Self::Error>;
    async fn acquire_lock_for_sync(&mut self, user: &User) -> Result<(), Self::Error>;
);
