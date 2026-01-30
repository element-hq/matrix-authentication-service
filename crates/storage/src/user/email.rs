// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{
    BrowserSession, Clock, UpstreamOAuthAuthorizationSession, User, UserEmail,
    UserEmailAuthentication, UserEmailAuthenticationCode, UserRegistration,
};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Pagination, pagination::Page, repository_impl};

/// Filter parameters for listing user emails
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct UserEmailFilter<'a> {
    user: Option<&'a User>,
    email: Option<&'a str>,
}

impl<'a> UserEmailFilter<'a> {
    /// Create a new [`UserEmailFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter for emails of a specific user
    #[must_use]
    pub fn for_user(mut self, user: &'a User) -> Self {
        self.user = Some(user);
        self
    }

    /// Filter for emails matching a specific email address
    ///
    /// The email address is case-insensitive
    #[must_use]
    pub fn for_email(mut self, email: &'a str) -> Self {
        self.email = Some(email);
        self
    }

    /// Get the user filter
    ///
    /// Returns [`None`] if no user filter is set
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.user
    }

    /// Get the email filter
    ///
    /// Returns [`None`] if no email filter is set
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email
    }
}

/// A [`UserEmailRepository`] helps interacting with [`UserEmail`] saved in the
/// storage backend
#[async_trait]
pub trait UserEmailRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an [`UserEmail`] by its ID
    ///
    /// Returns `None` if no [`UserEmail`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserEmail`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserEmail>, Self::Error>;

    /// Lookup an [`UserEmail`] by its email address for a [`User`]
    ///
    /// The email address is case-insensitive
    ///
    /// Returns `None` if no matching [`UserEmail`] was found
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] for whom to lookup the [`UserEmail`]
    /// * `email`: The email address to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find(&mut self, user: &User, email: &str) -> Result<Option<UserEmail>, Self::Error>;

    /// Lookup an [`UserEmail`] by its email address
    ///
    /// The email address is case-insensitive
    ///
    /// Returns `None` if no matching [`UserEmail`] was found or if multiple
    /// [`UserEmail`] are found
    ///
    /// # Parameters
    /// * `email`: The email address to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_email(&mut self, email: &str) -> Result<Option<UserEmail>, Self::Error>;

    /// Get all [`UserEmail`] of a [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] for whom to lookup the [`UserEmail`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn all(&mut self, user: &User) -> Result<Vec<UserEmail>, Self::Error>;

    /// List [`UserEmail`] with the given filter and pagination
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
        filter: UserEmailFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserEmail>, Self::Error>;

    /// Count the [`UserEmail`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: UserEmailFilter<'_>) -> Result<usize, Self::Error>;

    /// Create a new [`UserEmail`] for a [`User`]
    ///
    /// Returns the newly created [`UserEmail`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `user`: The [`User`] for whom to create the [`UserEmail`]
    /// * `email`: The email address of the [`UserEmail`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        email: String,
    ) -> Result<UserEmail, Self::Error>;

    /// Delete a [`UserEmail`]
    ///
    /// # Parameters
    ///
    /// * `user_email`: The [`UserEmail`] to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn remove(&mut self, user_email: UserEmail) -> Result<(), Self::Error>;

    /// Delete all [`UserEmail`] with the given filter
    ///
    /// Returns the number of deleted [`UserEmail`]s
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn remove_bulk(&mut self, filter: UserEmailFilter<'_>) -> Result<usize, Self::Error>;

    /// Add a new [`UserEmailAuthentication`] for a [`BrowserSession`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `email`: The email address to add
    /// * `session`: The [`BrowserSession`] for which to add the
    ///   [`UserEmailAuthentication`]
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn add_authentication_for_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        session: &BrowserSession,
    ) -> Result<UserEmailAuthentication, Self::Error>;

    /// Add a new [`UserEmailAuthentication`] for a [`UserRegistration`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `email`: The email address to add
    /// * `registration`: The [`UserRegistration`] for which to add the
    ///   [`UserEmailAuthentication`]
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn add_authentication_for_registration(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        registration: &UserRegistration,
    ) -> Result<UserEmailAuthentication, Self::Error>;

    /// Add a new [`UserEmailAuthenticationCode`] for a
    /// [`UserEmailAuthentication`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `duration`: The duration for which the code is valid
    /// * `authentication`: The [`UserEmailAuthentication`] for which to add the
    ///   [`UserEmailAuthenticationCode`]
    /// * `code`: The code to add
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails or if the code
    /// already exists for this session
    async fn add_authentication_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        duration: chrono::Duration,
        authentication: &UserEmailAuthentication,
        code: String,
    ) -> Result<UserEmailAuthenticationCode, Self::Error>;

    /// Lookup a [`UserEmailAuthentication`]
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserEmailAuthentication`] to lookup
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn lookup_authentication(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserEmailAuthentication>, Self::Error>;

    /// Find a [`UserEmailAuthenticationCode`] by its code and session
    ///
    /// # Parameters
    ///
    /// * `authentication`: The [`UserEmailAuthentication`] to find the code for
    /// * `code`: The code of the [`UserEmailAuthentication`] to lookup
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn find_authentication_code(
        &mut self,
        authentication: &UserEmailAuthentication,
        code: &str,
    ) -> Result<Option<UserEmailAuthenticationCode>, Self::Error>;

    /// Complete a [`UserEmailAuthentication`] by using the given code
    ///
    /// Returns the completed [`UserEmailAuthentication`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock to use to generate timestamps
    /// * `authentication`: The [`UserEmailAuthentication`] to complete
    /// * `code`: The [`UserEmailAuthenticationCode`] to use
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn complete_authentication_with_code(
        &mut self,
        clock: &dyn Clock,
        authentication: UserEmailAuthentication,
        code: &UserEmailAuthenticationCode,
    ) -> Result<UserEmailAuthentication, Self::Error>;

    /// Complete a [`UserEmailAuthentication`] by using the given upstream oauth
    /// authorization session
    ///
    /// Returns the completed [`UserEmailAuthentication`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock to use to generate timestamps
    /// * `authentication`: The [`UserEmailAuthentication`] to complete
    /// * `upstream_oauth_authorization_session`: The
    ///   [`UpstreamOAuthAuthorizationSession`] to use
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails
    async fn complete_authentication_with_upstream(
        &mut self,
        clock: &dyn Clock,
        authentication: UserEmailAuthentication,
        upstream_oauth_authorization_session: &UpstreamOAuthAuthorizationSession,
    ) -> Result<UserEmailAuthentication, Self::Error>;

    /// Cleanup old email authentications
    ///
    /// This will delete email authentications with IDs up to and including
    /// `until`. Uses ULID cursor-based pagination for efficiency.
    /// Authentication codes will cascade-delete automatically.
    ///
    /// Returns the number of authentications deleted and the cursor for the
    /// next batch
    ///
    /// # Parameters
    ///
    /// * `since`: The cursor to start from (exclusive), or `None` to start from
    ///   the beginning
    /// * `until`: The maximum ULID to delete (inclusive upper bound)
    /// * `limit`: The maximum number of authentications to delete in this batch
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn cleanup_authentications(
        &mut self,
        since: Option<Ulid>,
        until: Ulid,
        limit: usize,
    ) -> Result<(usize, Option<Ulid>), Self::Error>;
}

repository_impl!(UserEmailRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserEmail>, Self::Error>;
    async fn find(&mut self, user: &User, email: &str) -> Result<Option<UserEmail>, Self::Error>;
    async fn find_by_email(&mut self, email: &str) -> Result<Option<UserEmail>, Self::Error>;

    async fn all(&mut self, user: &User) -> Result<Vec<UserEmail>, Self::Error>;
    async fn list(
        &mut self,
        filter: UserEmailFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UserEmail>, Self::Error>;
    async fn count(&mut self, filter: UserEmailFilter<'_>) -> Result<usize, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        email: String,
    ) -> Result<UserEmail, Self::Error>;
    async fn remove(&mut self, user_email: UserEmail) -> Result<(), Self::Error>;

    async fn remove_bulk(&mut self, filter: UserEmailFilter<'_>) -> Result<usize, Self::Error>;

    async fn add_authentication_for_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        session: &BrowserSession,
    ) -> Result<UserEmailAuthentication, Self::Error>;

    async fn add_authentication_for_registration(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        registration: &UserRegistration,
    ) -> Result<UserEmailAuthentication, Self::Error>;

    async fn add_authentication_code(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        duration: chrono::Duration,
        authentication: &UserEmailAuthentication,
        code: String,
    ) -> Result<UserEmailAuthenticationCode, Self::Error>;

    async fn lookup_authentication(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserEmailAuthentication>, Self::Error>;

    async fn find_authentication_code(
        &mut self,
        authentication: &UserEmailAuthentication,
        code: &str,
    ) -> Result<Option<UserEmailAuthenticationCode>, Self::Error>;

    async fn complete_authentication_with_code(
        &mut self,
        clock: &dyn Clock,
        authentication: UserEmailAuthentication,
        code: &UserEmailAuthenticationCode,
    ) -> Result<UserEmailAuthentication, Self::Error>;

    async fn complete_authentication_with_upstream(
        &mut self,
        clock: &dyn Clock,
        authentication: UserEmailAuthentication,
        upstream_oauth_authorization_session: &UpstreamOAuthAuthorizationSession,
    ) -> Result<UserEmailAuthentication, Self::Error>;

    async fn cleanup_authentications(
        &mut self,
        since: Option<Ulid>,
        until: Ulid,
        limit: usize,
    ) -> Result<(usize, Option<Ulid>), Self::Error>;
);
