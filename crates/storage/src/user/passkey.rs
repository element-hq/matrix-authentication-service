// Copyright 2025, 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{BrowserSession, Clock, User, UserPasskey, UserPasskeyChallenge};
use rand_core::RngCore;
use ulid::Ulid;
use webauthn_rp::response::{AuthTransports, CredentialId};

use crate::{Page, Pagination, repository_impl};

/// Filter parameters for listing user passkeys
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct UserPasskeyFilter<'a> {
    user: Option<&'a User>,
}

impl<'a> UserPasskeyFilter<'a> {
    /// Create a new [`UserPasskeyFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter for passkeys of a specific user
    #[must_use]
    pub fn for_user(mut self, user: &'a User) -> Self {
        self.user = Some(user);
        self
    }

    /// Get the user filter
    ///
    /// Returns [`None`] if no user filter is set
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.user
    }
}

/// A [`UserPasskeyRepository`] helps interacting with [`UserPasskey`] saved in
/// the storage backend
#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait UserPasskeyRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an [`UserPasskey`] by its ID
    ///
    /// Returns `None` if no [`UserPasskey`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserPasskey`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserPasskey>, Self::Error>;

    /// Lookup an [`UserPasskey`] by its credential ID
    ///
    /// Returns `None` if no matching [`UserPasskey`] was found
    ///
    /// # Parameters
    ///
    /// * `credential_id`: The credential ID to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find(
        &mut self,
        credential_id: &CredentialId<Vec<u8>>,
    ) -> Result<Option<UserPasskey>, Self::Error>;

    /// Get all [`UserPasskey`] of a [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] for whom to lookup the [`UserPasskey`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn all(&mut self, user: &User) -> Result<Vec<UserPasskey>, Self::Error>;

    /// List [`UserPasskey`] with the given filter and pagination
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
        filter: UserPasskeyFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserPasskey>, Self::Error>;

    /// Count the [`UserPasskey`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: UserPasskeyFilter<'_>) -> Result<usize, Self::Error>;

    /// Create a new [`UserPasskey`] for a [`User`]
    ///
    /// Returns the newly created [`UserPasskey`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `user`: The [`User`] for whom to create the [`UserPasskey`]
    /// * `name`: The optional name for the [`UserPasskey`]
    /// * `data`: The passkey data of the [`UserPasskey`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        name: Option<String>,
        credential_id: CredentialId<Vec<u8>>,
        transports: AuthTransports,
        static_state: Vec<u8>,
        dynamic_state: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<UserPasskey, Self::Error>;

    /// Rename a [`UserPasskey`]
    ///
    /// Returns the modified [`UserPasskey`]
    ///
    /// # Parameters
    ///
    /// * `user_passkey`: The [`UserPasskey`] to rename
    /// * `name`: The new name
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn rename(
        &mut self,
        user_passkey: UserPasskey,
        name: String,
    ) -> Result<UserPasskey, Self::Error>;

    /// Update a [`UserPasskey`]
    ///
    /// Returns the modified [`UserPasskey`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock to use
    /// * `user_passkey`: The [`UserPasskey`] to update
    /// * `data`: The new passkey data
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn update(
        &mut self,
        clock: &dyn Clock,
        user_passkey: UserPasskey,
        dynamic_state: Vec<u8>,
    ) -> Result<UserPasskey, Self::Error>;

    /// Delete a [`UserPasskey`]
    ///
    /// # Parameters
    ///
    /// * `user_passkey`: The [`UserPasskey`] to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn remove(&mut self, user_passkey: UserPasskey) -> Result<(), Self::Error>;

    /// Add a new [`UserPasskeyChallenge`] for a [`BrowserSession`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `state`: The challenge state to add
    /// * `session`: The [`BrowserSession`] for which to add the
    ///   [`UserPasskeyChallenge`]
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn add_challenge_for_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        state: Vec<u8>,
        session: &BrowserSession,
    ) -> Result<UserPasskeyChallenge, Self::Error>;

    /// Add a new [`UserPasskeyChallenge`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `state`: The challenge state to add
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn add_challenge(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        state: Vec<u8>,
    ) -> Result<UserPasskeyChallenge, Self::Error>;

    /// Lookup a [`UserPasskeyChallenge`]
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserPasskeyChallenge`] to lookup
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn lookup_challenge(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserPasskeyChallenge>, Self::Error>;

    /// Complete a [`UserPasskeyChallenge`] by using the given code
    ///
    /// Returns the completed [`UserPasskeyChallenge`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock to use to generate timestamps
    /// * `challenge`: The [`UserPasskeyChallenge`] to complete
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn complete_challenge(
        &mut self,
        clock: &dyn Clock,
        user_passkey_challenge: UserPasskeyChallenge,
    ) -> Result<UserPasskeyChallenge, Self::Error>;

    /// Cleanup old challenges
    ///
    /// Returns the number of challenges that were cleaned up
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to get the current time
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn cleanup_challenges(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error>;
}

repository_impl!(UserPasskeyRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserPasskey>, Self::Error>;
    async fn find(&mut self, credential_id: &CredentialId<Vec<u8>>) -> Result<Option<UserPasskey>, Self::Error>;
    async fn all(&mut self, user: &User) -> Result<Vec<UserPasskey>, Self::Error>;

    async fn list(
        &mut self,
        filter: UserPasskeyFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserPasskey>, Self::Error>;
    async fn count(&mut self, filter: UserPasskeyFilter<'_>) -> Result<usize, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        name: Option<String>,
        credential_id: CredentialId<Vec<u8>>,
        transports: AuthTransports,
        static_state: Vec<u8>,
        dynamic_state: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<UserPasskey, Self::Error>;
    async fn rename(
        &mut self,
        user_passkey: UserPasskey,
        name: String,
    ) -> Result<UserPasskey, Self::Error>;
    async fn update(
        &mut self,
        clock: &dyn Clock,
        user_passkey: UserPasskey,
        dynamic_state: Vec<u8>,
    ) -> Result<UserPasskey, Self::Error>;
    async fn remove(&mut self, user_passkey: UserPasskey) -> Result<(), Self::Error>;

    async fn add_challenge_for_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        state: Vec<u8>,
        session: &BrowserSession,
    ) -> Result<UserPasskeyChallenge, Self::Error>;
    async fn add_challenge(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        state: Vec<u8>,
    ) -> Result<UserPasskeyChallenge, Self::Error>;

    async fn lookup_challenge(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserPasskeyChallenge>, Self::Error>;

    async fn complete_challenge(
        &mut self,
        clock: &dyn Clock,
        user_passkey_challenge: UserPasskeyChallenge,
    ) -> Result<UserPasskeyChallenge, Self::Error>;

    async fn cleanup_challenges(&mut self, clock: &dyn Clock) -> Result<usize, Self::Error>;
);
