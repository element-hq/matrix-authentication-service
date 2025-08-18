// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{
    Clock, UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, UpstreamOAuthProvider,
};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Pagination, pagination::Page, repository_impl};

/// Filter parameters for listing upstream OAuth sessions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct UpstreamOAuthSessionFilter<'a> {
    provider: Option<&'a UpstreamOAuthProvider>,
    sub_claim: Option<&'a str>,
    sid_claim: Option<&'a str>,
}

impl<'a> UpstreamOAuthSessionFilter<'a> {
    /// Create a new [`UpstreamOAuthSessionFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the upstream OAuth provider for which to list sessions
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

    /// Set the `sub` claim to filter by
    #[must_use]
    pub fn with_sub_claim(mut self, sub_claim: &'a str) -> Self {
        self.sub_claim = Some(sub_claim);
        self
    }

    /// Get the `sub` claim filter
    ///
    /// Returns [`None`] if no filter was set
    #[must_use]
    pub fn sub_claim(&self) -> Option<&str> {
        self.sub_claim
    }

    /// Set the `sid` claim to filter by
    #[must_use]
    pub fn with_sid_claim(mut self, sid_claim: &'a str) -> Self {
        self.sid_claim = Some(sid_claim);
        self
    }

    /// Get the `sid` claim filter
    ///
    /// Returns [`None`] if no filter was set
    #[must_use]
    pub fn sid_claim(&self) -> Option<&str> {
        self.sid_claim
    }
}

/// An [`UpstreamOAuthSessionRepository`] helps interacting with
/// [`UpstreamOAuthAuthorizationSession`] saved in the storage backend
#[async_trait]
pub trait UpstreamOAuthSessionRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a session by its ID
    ///
    /// Returns `None` if the session does not exist
    ///
    /// # Parameters
    ///
    /// * `id`: the ID of the session to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UpstreamOAuthAuthorizationSession>, Self::Error>;

    /// Add a session to the database
    ///
    /// Returns the newly created session
    ///
    /// # Parameters
    ///
    /// * `rng`: the random number generator to use
    /// * `clock`: the clock source
    /// * `upstream_oauth_provider`: the upstream OAuth provider for which to
    ///   create the session
    /// * `state`: the authorization grant `state` parameter sent to the
    ///   upstream OAuth provider
    /// * `code_challenge_verifier`: the code challenge verifier used in this
    ///   session, if PKCE is being used
    /// * `nonce`: the `nonce` used in this session if in OIDC mode
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        state: String,
        code_challenge_verifier: Option<String>,
        nonce: Option<String>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    /// Mark a session as completed and associate the given link
    ///
    /// Returns the updated session
    ///
    /// # Parameters
    ///
    /// * `clock`: the clock source
    /// * `upstream_oauth_authorization_session`: the session to update
    /// * `upstream_oauth_link`: the link to associate with the session
    /// * `id_token`: the ID token returned by the upstream OAuth provider, if
    ///   present
    /// * `id_token_claims`: the claims contained in the ID token, if present
    /// * `extra_callback_parameters`: the extra query parameters returned in
    ///   the callback, if any
    /// * `userinfo`: the user info returned by the upstream OAuth provider, if
    ///   requested
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    #[expect(clippy::too_many_arguments)]
    async fn complete_with_link(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
        upstream_oauth_link: &UpstreamOAuthLink,
        id_token: Option<String>,
        id_token_claims: Option<serde_json::Value>,
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    /// Mark a session as consumed
    ///
    /// Returns the updated session
    ///
    /// # Parameters
    ///
    /// * `clock`: the clock source
    /// * `upstream_oauth_authorization_session`: the session to consume
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn consume(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    /// List [`UpstreamOAuthAuthorizationSession`] with the given filter and
    /// pagination
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
        filter: UpstreamOAuthSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthAuthorizationSession>, Self::Error>;

    /// Count the number of [`UpstreamOAuthAuthorizationSession`] with the given
    /// filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter to apply
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: UpstreamOAuthSessionFilter<'_>)
    -> Result<usize, Self::Error>;
}

repository_impl!(UpstreamOAuthSessionRepository:
    async fn lookup(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UpstreamOAuthAuthorizationSession>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        upstream_oauth_provider: &UpstreamOAuthProvider,
        state: String,
        code_challenge_verifier: Option<String>,
        nonce: Option<String>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    async fn complete_with_link(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
        upstream_oauth_link: &UpstreamOAuthLink,
        id_token: Option<String>,
        id_token_claims: Option<serde_json::Value>,
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    async fn consume(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    async fn list(
        &mut self,
        filter: UpstreamOAuthSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<UpstreamOAuthAuthorizationSession>, Self::Error>;

    async fn count(&mut self, filter: UpstreamOAuthSessionFilter<'_>) -> Result<usize, Self::Error>;
);
