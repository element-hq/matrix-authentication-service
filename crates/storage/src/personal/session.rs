// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{Clock, Device, User, personal::session::PersonalSession};
use oauth2_types::scope::Scope;
use rand_core::RngCore;
use ulid::Ulid;

use crate::repository_impl;

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
        owner_user: &User,
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
}

repository_impl!(PersonalSessionRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalSession>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        owner_user: &User,
        actor_user: &User,
        human_name: String,
        scope: Scope,
    ) -> Result<PersonalSession, Self::Error>;

    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        personal_session: PersonalSession,
    ) -> Result<PersonalSession, Self::Error>;
);
