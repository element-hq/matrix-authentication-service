// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{Clock, UpstreamOAuthLink, UpstreamOAuthLinkToken};
use rand_core::RngCore;
use ulid::Ulid;

use crate::repository_impl;

/// An [`UpstreamOAuthLinkTokenRepository`] helps interacting with
/// [`UpstreamOAuthLinkToken`] with the storage backend
#[async_trait]
pub trait UpstreamOAuthLinkTokenRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an upstream OAuth link token by its ID
    ///
    /// Returns `None` if the token does not exist
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the upstream OAuth link token to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthLinkToken>, Self::Error>;

    /// Find the stored token for a given upstream OAuth link
    ///
    /// Returns `None` if no token is stored for this link
    ///
    /// # Parameters
    ///
    /// * `link`: The upstream OAuth link to find the token for
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_link(
        &mut self,
        link: &UpstreamOAuthLink,
    ) -> Result<Option<UpstreamOAuthLinkToken>, Self::Error>;

    /// Add a new upstream OAuth link token
    ///
    /// Returns the newly created token
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `link`: The upstream OAuth link to associate the token with
    /// * `encrypted_access_token`: The encrypted access token
    /// * `encrypted_refresh_token`: The encrypted refresh token, if any
    /// * `expires_at`: When the access token expires, if known
    /// * `scope`: The scope of the token, if known
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    #[expect(clippy::too_many_arguments)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        link: &UpstreamOAuthLink,
        encrypted_access_token: String,
        encrypted_refresh_token: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        scope: Option<String>,
    ) -> Result<UpstreamOAuthLinkToken, Self::Error>;

    /// Update the tokens for an existing upstream OAuth link token
    ///
    /// Returns the updated token
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `link_token`: The existing link token to update
    /// * `encrypted_access_token`: The new encrypted access token
    /// * `encrypted_refresh_token`: The new encrypted refresh token, if any
    /// * `expires_at`: When the new access token expires, if known
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn update_tokens(
        &mut self,
        clock: &dyn Clock,
        link_token: UpstreamOAuthLinkToken,
        encrypted_access_token: String,
        encrypted_refresh_token: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UpstreamOAuthLinkToken, Self::Error>;
}

repository_impl!(UpstreamOAuthLinkTokenRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UpstreamOAuthLinkToken>, Self::Error>;

    async fn find_by_link(
        &mut self,
        link: &UpstreamOAuthLink,
    ) -> Result<Option<UpstreamOAuthLinkToken>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        link: &UpstreamOAuthLink,
        encrypted_access_token: String,
        encrypted_refresh_token: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        scope: Option<String>,
    ) -> Result<UpstreamOAuthLinkToken, Self::Error>;

    async fn update_tokens(
        &mut self,
        clock: &dyn Clock,
        link_token: UpstreamOAuthLinkToken,
        encrypted_access_token: String,
        encrypted_refresh_token: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UpstreamOAuthLinkToken, Self::Error>;
);
