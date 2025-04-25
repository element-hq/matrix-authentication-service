// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{BrowserSession, Client, Device, Session, User};
use oauth2_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, Pagination, pagination::Page, repository_impl};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuth2SessionState {
    Active,
    Finished,
}

impl OAuth2SessionState {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_finished(self) -> bool {
        matches!(self, Self::Finished)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientKind {
    Static,
    Dynamic,
}

impl ClientKind {
    pub fn is_static(self) -> bool {
        matches!(self, Self::Static)
    }
}

/// Filter parameters for listing OAuth 2.0 sessions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OAuth2SessionFilter<'a> {
    user: Option<&'a User>,
    any_user: Option<bool>,
    browser_session: Option<&'a BrowserSession>,
    device: Option<&'a Device>,
    client: Option<&'a Client>,
    client_kind: Option<ClientKind>,
    state: Option<OAuth2SessionState>,
    scope: Option<&'a Scope>,
    last_active_before: Option<DateTime<Utc>>,
    last_active_after: Option<DateTime<Utc>>,
}

impl<'a> OAuth2SessionFilter<'a> {
    /// Create a new [`OAuth2SessionFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// List sessions for a specific user
    #[must_use]
    pub fn for_user(mut self, user: &'a User) -> Self {
        self.user = Some(user);
        self
    }

    /// Get the user filter
    ///
    /// Returns [`None`] if no user filter was set
    #[must_use]
    pub fn user(&self) -> Option<&'a User> {
        self.user
    }

    /// List sessions which belong to any user
    #[must_use]
    pub fn for_any_user(mut self) -> Self {
        self.any_user = Some(true);
        self
    }

    /// List sessions which belong to no user
    #[must_use]
    pub fn for_no_user(mut self) -> Self {
        self.any_user = Some(false);
        self
    }

    /// Get the 'any user' filter
    ///
    /// Returns [`None`] if no 'any user' filter was set
    #[must_use]
    pub fn any_user(&self) -> Option<bool> {
        self.any_user
    }

    /// List sessions started by a specific browser session
    #[must_use]
    pub fn for_browser_session(mut self, browser_session: &'a BrowserSession) -> Self {
        self.browser_session = Some(browser_session);
        self
    }

    /// Get the browser session filter
    ///
    /// Returns [`None`] if no browser session filter was set
    #[must_use]
    pub fn browser_session(&self) -> Option<&'a BrowserSession> {
        self.browser_session
    }

    /// List sessions for a specific client
    #[must_use]
    pub fn for_client(mut self, client: &'a Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Get the client filter
    ///
    /// Returns [`None`] if no client filter was set
    #[must_use]
    pub fn client(&self) -> Option<&'a Client> {
        self.client
    }

    /// List only static clients
    #[must_use]
    pub fn only_static_clients(mut self) -> Self {
        self.client_kind = Some(ClientKind::Static);
        self
    }

    /// List only dynamic clients
    #[must_use]
    pub fn only_dynamic_clients(mut self) -> Self {
        self.client_kind = Some(ClientKind::Dynamic);
        self
    }

    /// Get the client kind filter
    ///
    /// Returns [`None`] if no client kind filter was set
    #[must_use]
    pub fn client_kind(&self) -> Option<ClientKind> {
        self.client_kind
    }

    /// Only return sessions with a last active time before the given time
    #[must_use]
    pub fn with_last_active_before(mut self, last_active_before: DateTime<Utc>) -> Self {
        self.last_active_before = Some(last_active_before);
        self
    }

    /// Only return sessions with a last active time after the given time
    #[must_use]
    pub fn with_last_active_after(mut self, last_active_after: DateTime<Utc>) -> Self {
        self.last_active_after = Some(last_active_after);
        self
    }

    /// Get the last active before filter
    ///
    /// Returns [`None`] if no client filter was set
    #[must_use]
    pub fn last_active_before(&self) -> Option<DateTime<Utc>> {
        self.last_active_before
    }

    /// Get the last active after filter
    ///
    /// Returns [`None`] if no client filter was set
    #[must_use]
    pub fn last_active_after(&self) -> Option<DateTime<Utc>> {
        self.last_active_after
    }

    /// Only return active sessions
    #[must_use]
    pub fn active_only(mut self) -> Self {
        self.state = Some(OAuth2SessionState::Active);
        self
    }

    /// Only return finished sessions
    #[must_use]
    pub fn finished_only(mut self) -> Self {
        self.state = Some(OAuth2SessionState::Finished);
        self
    }

    /// Get the state filter
    ///
    /// Returns [`None`] if no state filter was set
    #[must_use]
    pub fn state(&self) -> Option<OAuth2SessionState> {
        self.state
    }

    /// Only return sessions with the given scope
    #[must_use]
    pub fn with_scope(mut self, scope: &'a Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Get the scope filter
    ///
    /// Returns [`None`] if no scope filter was set
    #[must_use]
    pub fn scope(&self) -> Option<&'a Scope> {
        self.scope
    }

    /// Only return sessions that have the given device in their scope
    #[must_use]
    pub fn for_device(mut self, device: &'a Device) -> Self {
        self.device = Some(device);
        self
    }

    /// Get the device filter
    ///
    /// Returns [`None`] if no device filter was set
    #[must_use]
    pub fn device(&self) -> Option<&'a Device> {
        self.device
    }
}

/// An [`OAuth2SessionRepository`] helps interacting with [`Session`]
/// saved in the storage backend
#[async_trait]
pub trait OAuth2SessionRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an [`Session`] by its ID
    ///
    /// Returns `None` if no [`Session`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`Session`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Session>, Self::Error>;

    /// Create a new [`Session`] with the given parameters
    ///
    /// Returns the newly created [`Session`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `client`: The [`Client`] which created the [`Session`]
    /// * `user`: The [`User`] for which the session should be created, if any
    /// * `user_session`: The [`BrowserSession`] of the user which completed the
    ///   authorization, if any
    /// * `scope`: The [`Scope`] of the [`Session`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user: Option<&User>,
        user_session: Option<&BrowserSession>,
        scope: Scope,
    ) -> Result<Session, Self::Error>;

    /// Create a new [`Session`] out of a [`Client`] and a [`BrowserSession`]
    ///
    /// Returns the newly created [`Session`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `client`: The [`Client`] which created the [`Session`]
    /// * `user_session`: The [`BrowserSession`] of the user which completed the
    ///   authorization
    /// * `scope`: The [`Scope`] of the [`Session`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add_from_browser_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user_session: &BrowserSession,
        scope: Scope,
    ) -> Result<Session, Self::Error> {
        self.add(
            rng,
            clock,
            client,
            Some(&user_session.user),
            Some(user_session),
            scope,
        )
        .await
    }

    /// Create a new [`Session`] for a [`Client`] using the client credentials
    /// flow
    ///
    /// Returns the newly created [`Session`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `client`: The [`Client`] which created the [`Session`]
    /// * `scope`: The [`Scope`] of the [`Session`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add_from_client_credentials(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        scope: Scope,
    ) -> Result<Session, Self::Error> {
        self.add(rng, clock, client, None, None, scope).await
    }

    /// Mark a [`Session`] as finished
    ///
    /// Returns the updated [`Session`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `session`: The [`Session`] to mark as finished
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn finish(&mut self, clock: &dyn Clock, session: Session)
    -> Result<Session, Self::Error>;

    /// Mark all the [`Session`] matching the given filter as finished
    ///
    /// Returns the number of sessions affected
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `filter`: The filter parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn finish_bulk(
        &mut self,
        clock: &dyn Clock,
        filter: OAuth2SessionFilter<'_>,
    ) -> Result<usize, Self::Error>;

    /// List [`Session`]s matching the given filter and pagination parameters
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
        filter: OAuth2SessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<Session>, Self::Error>;

    /// Count [`Session`]s matching the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: OAuth2SessionFilter<'_>) -> Result<usize, Self::Error>;

    /// Record a batch of [`Session`] activity
    ///
    /// # Parameters
    ///
    /// * `activity`: A list of tuples containing the session ID, the last
    ///   activity timestamp and the IP address of the client
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn record_batch_activity(
        &mut self,
        activity: Vec<(Ulid, DateTime<Utc>, Option<IpAddr>)>,
    ) -> Result<(), Self::Error>;

    /// Record the user agent of a [`Session`]
    ///
    /// # Parameters
    ///
    /// * `session`: The [`Session`] to record the user agent for
    /// * `user_agent`: The user agent to record
    async fn record_user_agent(
        &mut self,
        session: Session,
        user_agent: String,
    ) -> Result<Session, Self::Error>;

    /// Set the human name of a [`Session`]
    ///
    /// # Parameters
    ///
    /// * `session`: The [`Session`] to set the human name for
    /// * `human_name`: The human name to set
    async fn set_human_name(
        &mut self,
        session: Session,
        human_name: Option<String>,
    ) -> Result<Session, Self::Error>;
}

repository_impl!(OAuth2SessionRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Session>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user: Option<&User>,
        user_session: Option<&BrowserSession>,
        scope: Scope,
    ) -> Result<Session, Self::Error>;

    async fn add_from_browser_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        user_session: &BrowserSession,
        scope: Scope,
    ) -> Result<Session, Self::Error>;

    async fn add_from_client_credentials(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        client: &Client,
        scope: Scope,
    ) -> Result<Session, Self::Error>;

    async fn finish(&mut self, clock: &dyn Clock, session: Session)
        -> Result<Session, Self::Error>;

    async fn finish_bulk(
        &mut self,
        clock: &dyn Clock,
        filter: OAuth2SessionFilter<'_>,
    ) -> Result<usize, Self::Error>;

    async fn list(
        &mut self,
        filter: OAuth2SessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<Session>, Self::Error>;

    async fn count(&mut self, filter: OAuth2SessionFilter<'_>) -> Result<usize, Self::Error>;

    async fn record_batch_activity(
        &mut self,
        activity: Vec<(Ulid, DateTime<Utc>, Option<IpAddr>)>,
    ) -> Result<(), Self::Error>;

    async fn record_user_agent(
        &mut self,
        session: Session,
        user_agent: String,
    ) -> Result<Session, Self::Error>;

    async fn set_human_name(
        &mut self,
        session: Session,
        human_name: Option<String>,
    ) -> Result<Session, Self::Error>;
);
