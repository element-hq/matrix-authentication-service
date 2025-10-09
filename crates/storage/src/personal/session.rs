// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    Client, Clock, Device, User,
    personal::session::{PersonalSession, PersonalSessionOwner},
};
use oauth2_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Page, Pagination, repository_impl};

/// A [`PersonalSessionRepository`] helps interacting with
/// [`PersonalSession`] saved in the storage backend
#[async_trait]
pub trait PersonalSessionRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a Personal session by its ID
    ///
    /// Returns the Personal session if it exists, `None` otherwise
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the Personal session to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalSession>, Self::Error>;

    /// Start a new Personal session
    ///
    /// Returns the newly created Personal session
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `owner_user`: The user that will own the personal session
    /// * `actor_user`: The user that will be represented by the personal
    ///   session
    /// * `device`: The device ID of this session
    /// * `human_name`: The human-readable name of the session provided by the
    ///   client or the user
    /// * `scope`: The [`Scope`] of the [`PersonalSession`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        owner: PersonalSessionOwner,
        actor_user: &User,
        human_name: String,
        scope: Scope,
    ) -> Result<PersonalSession, Self::Error>;

    /// End a Personal session
    ///
    /// Returns the ended Personal session
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `Personal_session`: The Personal session to end
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        personal_session: PersonalSession,
    ) -> Result<PersonalSession, Self::Error>;

    /// List [`PersonalSession`]s matching the given filter and pagination
    /// parameters
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
        filter: PersonalSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<PersonalSession>, Self::Error>;

    /// Count [`PersonalSession`]s matching the given filter
    ///
    /// # Parameters
    ///
    /// * `filter`: The filter parameters
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: PersonalSessionFilter<'_>) -> Result<usize, Self::Error>;
}

repository_impl!(PersonalSessionRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalSession>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        owner: PersonalSessionOwner,
        actor_user: &User,
        human_name: String,
        scope: Scope,
    ) -> Result<PersonalSession, Self::Error>;

    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        personal_session: PersonalSession,
    ) -> Result<PersonalSession, Self::Error>;

    async fn list(
        &mut self,
        filter: PersonalSessionFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<PersonalSession>, Self::Error>;

    async fn count(&mut self, filter: PersonalSessionFilter<'_>) -> Result<usize, Self::Error>;
);

/// Filter parameters for listing personal sessions
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PersonalSessionFilter<'a> {
    owner_user: Option<&'a User>,
    owner_oauth2_client: Option<&'a Client>,
    actor_user: Option<&'a User>,
    device: Option<&'a Device>,
    state: Option<PersonalSessionState>,
    scope: Option<&'a Scope>,
    last_active_before: Option<DateTime<Utc>>,
    last_active_after: Option<DateTime<Utc>>,
}

/// Filter for what state a personal session is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersonalSessionState {
    /// The personal session is active, which means it either
    /// has active access tokens or can have new access tokens generated.
    Active,
    /// The personal session is revoked, which means no more access tokens
    /// can be generated and none are active.
    Revoked,
}

impl<'a> PersonalSessionFilter<'a> {
    /// Create a new [`PersonalSessionFilter`] with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// List sessions owned by a specific user
    #[must_use]
    pub fn for_owner_user(mut self, user: &'a User) -> Self {
        self.owner_user = Some(user);
        self
    }

    /// Get the owner user filter
    ///
    /// Returns [`None`] if no user filter was set
    #[must_use]
    pub fn owner_oauth2_client(&self) -> Option<&'a Client> {
        self.owner_oauth2_client
    }

    /// List sessions owned by a specific user
    #[must_use]
    pub fn for_owner_oauth2_client(mut self, client: &'a Client) -> Self {
        self.owner_oauth2_client = Some(client);
        self
    }

    /// Get the owner user filter
    ///
    /// Returns [`None`] if no user filter was set
    #[must_use]
    pub fn owner_user(&self) -> Option<&'a User> {
        self.owner_user
    }

    /// List sessions acting as a specific user
    #[must_use]
    pub fn for_actor_user(mut self, user: &'a User) -> Self {
        self.actor_user = Some(user);
        self
    }

    /// Get the actor user filter
    ///
    /// Returns [`None`] if no user filter was set
    #[must_use]
    pub fn actor_user(&self) -> Option<&'a User> {
        self.actor_user
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
        self.state = Some(PersonalSessionState::Active);
        self
    }

    /// Only return finished sessions
    #[must_use]
    pub fn finished_only(mut self) -> Self {
        self.state = Some(PersonalSessionState::Revoked);
        self
    }

    /// Get the state filter
    ///
    /// Returns [`None`] if no state filter was set
    #[must_use]
    pub fn state(&self) -> Option<PersonalSessionState> {
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
