// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use mas_data_model::{BrowserSession, Clock, LoginSession, User};
use rand_core::RngCore;
use ulid::Ulid;

use crate::repository_impl;

/// A [`LoginSessionRepository`] helps interacting with [`LoginSession`]
/// saved in the storage backend
#[async_trait]
pub trait LoginSessionRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`LoginSession`] by its ID
    ///
    /// Returns `None` if no [`LoginSession`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`LoginSession`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<LoginSession>, Self::Error>;

    /// Create a new [`LoginSession`]
    ///
    /// Returns the newly created [`LoginSession`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `ip_address`: The IP address of the user agent, if any
    /// * `user_agent`: The user agent of the user agent, if any
    /// * `post_auth_action`: The post auth action to execute once the login
    ///   flow completes, if any
    /// * `login_hint`: The untrusted client-supplied `login_hint`, if any
    /// * `target_user`: The user resolved from a verified `id_token_hint`, if
    ///   any
    /// * `target_user_session`: The browser session resolved from the `sid`
    ///   claim of a verified `id_token_hint`, if any
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    #[expect(clippy::too_many_arguments)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        post_auth_action: Option<serde_json::Value>,
        login_hint: Option<String>,
        target_user: Option<&User>,
        target_user_session: Option<&BrowserSession>,
    ) -> Result<LoginSession, Self::Error>;

    /// Mark a [`LoginSession`] as completed by the given browser session
    ///
    /// Returns the updated [`LoginSession`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `login_session`: The [`LoginSession`] to complete
    /// * `browser_session`: The browser session which completed the flow
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails, or if the
    /// login session was already completed
    async fn complete(
        &mut self,
        clock: &dyn Clock,
        login_session: LoginSession,
        browser_session: &BrowserSession,
    ) -> Result<LoginSession, Self::Error>;
}

repository_impl!(LoginSessionRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<LoginSession>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        post_auth_action: Option<serde_json::Value>,
        login_hint: Option<String>,
        target_user: Option<&User>,
        target_user_session: Option<&BrowserSession>,
    ) -> Result<LoginSession, Self::Error>;
    async fn complete(
        &mut self,
        clock: &dyn Clock,
        login_session: LoginSession,
        browser_session: &BrowserSession,
    ) -> Result<LoginSession, Self::Error>;
);
