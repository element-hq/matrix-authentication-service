// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, UpstreamOAuthProvider};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, repository_impl};

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
    /// * `extra_callback_parameters`: the extra query parameters returned in
    ///   the callback, if any
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn complete_with_link(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
        upstream_oauth_link: &UpstreamOAuthLink,
        id_token: Option<String>,
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
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;

    async fn consume(
        &mut self,
        clock: &dyn Clock,
        upstream_oauth_authorization_session: UpstreamOAuthAuthorizationSession,
    ) -> Result<UpstreamOAuthAuthorizationSession, Self::Error>;
);
