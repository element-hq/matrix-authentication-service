// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{UpstreamOAuthLink, UpstreamOAuthProvider, User};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, Pagination, pagination::Page, repository_impl};

/// Filter parameters for listing upstream OAuth links
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct UpstreamOAuthLinkFilter<'a> {
    // XXX: we might also want to filter for links without a user linked to them
    user: Option<&'a User>,
    provider: Option<&'a UpstreamOAuthProvider>,
    provider_enabled: Option<bool>,
    subject: Option<&'a str>,
}

impl<'a> UpstreamOAuthLinkFilter<'a> {
    /// Create a new [`UpstreamOAuthLinkFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the user who owns the upstream OAuth links
    #[must_use]
    pub fn for_user(mut self, user: &'a User) -> Self {
        self.user = Some(user);
        self
    }

    /// Get the user filter
    ///
    /// Returns [`None`] if no filter was set
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.user
    }

    /// Set the upstream OAuth provider for which to list links
    #[must_use]
    pub fn for_provider(mut self, provider: &'a UpstreamOAuthProvider) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Get the upstream OAuth provider filter
    ///
    /// Returns [`None`] if no filter was set
    #[must_use]
    pub fn provider(&self) -> Option<&UpstreamOAuthProvider> {
        self.provider
    }

    /// Set whether to filter for enabled providers
    #[must_use]
    pub const fn enabled_providers_only(mut self) -> Self {
        self.provider_enabled = Some(true);
        self
    }

    /// Set whether to filter for disabled providers
    #[must_use]
    pub const fn disabled_providers_only(mut self) -> Self {
        self.provider_enabled = Some(false);
        self
    }

    /// Get the provider enabled filter
    #[must_use]
    pub const fn provider_enabled(&self) -> Option<bool> {
        self.provider_enabled
    }

    /// Set the subject filter
    #[must_use]
    pub const fn for_subject(mut self, subject: &'a str) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Get the subject filter
    #[must_use]
    pub const fn subject(&self) -> Option<&str> {
        self.subject
    }
}

/// An [`UpstreamOAuthLinkRepository`] helps interacting with
/// [`UpstreamOAuthLink`] with the storage backend
#[async_trait]
pub trait UpstreamOAuthLinkRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an upstream OAuth link by its ID
    ///
    /// Returns `None` if the link does not exist
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the upstream OAuth link to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthLink>, Self::Error>;

    /// Find an upstream OAuth link for a provider by its subject
    ///
    /// Returns `None` if no matching upstream OAuth link was found
    ///
    /// # Parameters
    ///
    /// * `upstream_oauth_provider`: The upstream OAuth provider on which to
    ///   find the link
    /// * `subject`: The subject of the upstream OAuth link to find
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_subject(
        &mut self,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: &str,
    ) -> Result<Option<UpstreamOAuthLink>, Self::Error>;

    /// Add a new upstream OAuth link
    ///
    /// Returns the newly created upstream OAuth link
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `upsream_oauth_provider`: The upstream OAuth provider for which to
    ///   create the link
    /// * `subject`: The subject of the upstream OAuth link to create
    /// * `human_account_name`: A human-readable name for the upstream account
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: String,
        human_account_name: Option<String>,
    ) -> Result<UpstreamOAuthLink, Self::Error>;

    /// Associate an upstream OAuth link to a user
    ///
    /// Returns the updated upstream OAuth link
    ///
    /// # Parameters
    ///
    /// * `upstream_oauth_link`: The upstream OAuth link to update
    /// * `user`: The user to associate to the upstream OAuth link
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn associate_to_user(
        &mut self,
        upstream_oauth_link: &UpstreamOAuthLink,
        user: &User,
    ) -> Result<(), Self::Error>;

    /// List [`UpstreamOAuthLink`] with the given filter and pagination
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
        filter: UpstreamOAuthLinkFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthLink>, Self::Error>;

    /// Count the number of [`UpstreamOAuthLink`] with the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: UpstreamOAuthLinkFilter<'_>) -> Result<usize, Self::Error>;

    /// Delete a [`UpstreamOAuthLink`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `upstream_oauth_link`: The [`UpstreamOAuthLink`] to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn remove(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_link: UpstreamOAuthLink,
    ) -> Result<(), Self::Error>;
}

repository_impl!(UpstreamOAuthLinkRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthLink>, Self::Error>;

    async fn find_by_subject(
        &mut self,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: &str,
    ) -> Result<Option<UpstreamOAuthLink>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        subject: String,
        human_account_name: Option<String>,
    ) -> Result<UpstreamOAuthLink, Self::Error>;

    async fn associate_to_user(
        &mut self,
        upstream_oauth_link: &UpstreamOAuthLink,
        user: &User,
    ) -> Result<(), Self::Error>;

    async fn list(
        &mut self,
        filter: UpstreamOAuthLinkFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthLink>, Self::Error>;

    async fn count(&mut self, filter: UpstreamOAuthLinkFilter<'_>) -> Result<usize, Self::Error>;

    async fn remove(&mut self, clock: &dyn Clock, upstream_oauth_link: UpstreamOAuthLink) -> Result<(), Self::Error>;
);
