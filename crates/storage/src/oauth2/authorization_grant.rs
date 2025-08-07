// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{AuthorizationCode, AuthorizationGrant, Client, Clock, Session};
use oauth2_types::{requests::ResponseMode, scope::Scope};
use rand_core::RngCore;
use ulid::Ulid;
use url::Url;

use crate::repository_impl;

/// An [`OAuth2AuthorizationGrantRepository`] helps interacting with
/// [`AuthorizationGrant`] saved in the storage backend
#[async_trait]
pub trait OAuth2AuthorizationGrantRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Create a new authorization grant
    ///
    /// Returns the newly created authorization grant
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator
    /// * `clock`: The clock used to generate timestamps
    /// * `client`: The client that requested the authorization grant
    /// * `redirect_uri`: The redirect URI the client requested
    /// * `scope`: The scope the client requested
    /// * `code`: The authorization code used by this grant, if the `code`
    ///   `response_type` was requested
    /// * `state`: The state the client sent, if set
    /// * `nonce`: The nonce the client sent, if set
    /// * `response_mode`: The response mode the client requested
    /// * `response_type_id_token`: Whether the `id_token` `response_type` was
    ///   requested
    /// * `login_hint`: The login_hint the client sent, if set
    /// * `locale`: The locale the detected when the user asked for the
    ///   authorization grant
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    #[allow(clippy::too_many_arguments)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        redirect_uri: Url,
        scope: Scope,
        code: Option<AuthorizationCode>,
        state: Option<String>,
        nonce: Option<String>,
        response_mode: ResponseMode,
        response_type_id_token: bool,
        login_hint: Option<String>,
        locale: Option<String>,
    ) -> Result<AuthorizationGrant, Self::Error>;

    /// Lookup an authorization grant by its ID
    ///
    /// Returns the authorization grant if found, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the authorization grant to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<AuthorizationGrant>, Self::Error>;

    /// Find an authorization grant by its code
    ///
    /// Returns the authorization grant if found, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `code`: The code of the authorization grant to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_code(&mut self, code: &str)
    -> Result<Option<AuthorizationGrant>, Self::Error>;

    /// Fulfill an authorization grant, by giving the [`Session`] that it
    /// created
    ///
    /// Returns the updated authorization grant
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `session`: The session that was created using this authorization grant
    /// * `authorization_grant`: The authorization grant to fulfill
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        session: &Session,
        authorization_grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error>;

    /// Mark an authorization grant as exchanged
    ///
    /// Returns the updated authorization grant
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `authorization_grant`: The authorization grant to mark as exchanged
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        authorization_grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error>;
}

repository_impl!(OAuth2AuthorizationGrantRepository:
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        redirect_uri: Url,
        scope: Scope,
        code: Option<AuthorizationCode>,
        state: Option<String>,
        nonce: Option<String>,
        response_mode: ResponseMode,
        response_type_id_token: bool,
        login_hint: Option<String>,
        locale: Option<String>,
    ) -> Result<AuthorizationGrant, Self::Error>;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<AuthorizationGrant>, Self::Error>;

    async fn find_by_code(&mut self, code: &str)
        -> Result<Option<AuthorizationGrant>, Self::Error>;

    async fn fulfill(
        &mut self,
        clock: &dyn Clock,
        session: &Session,
        authorization_grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error>;

    async fn exchange(
        &mut self,
        clock: &dyn Clock,
        authorization_grant: AuthorizationGrant,
    ) -> Result<AuthorizationGrant, Self::Error>;
);
