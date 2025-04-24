// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use mas_data_model::{UserEmail, UserRecoverySession, UserRecoveryTicket};
use rand_core::RngCore;
use ulid::Ulid;

use crate::{Clock, repository_impl};

/// A [`UserRecoveryRepository`] helps interacting with [`UserRecoverySession`]
/// and [`UserRecoveryTicket`] saved in the storage backend
#[async_trait]
pub trait UserRecoveryRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an [`UserRecoverySession`] by its ID
    ///
    /// Returns `None` if no [`UserRecoverySession`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserRecoverySession`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup_session(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserRecoverySession>, Self::Error>;

    /// Create a new [`UserRecoverySession`] for the given email
    ///
    /// Returns the newly created [`UserRecoverySession`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `email`: The email to create the session for
    /// * `user_agent`: The user agent of the browser which initiated the
    ///   session
    /// * `ip_address`: The IP address of the browser which initiated the
    ///   session, if known
    /// * `locale`: The locale of the browser which initiated the session
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        user_agent: String,
        ip_address: Option<IpAddr>,
        locale: String,
    ) -> Result<UserRecoverySession, Self::Error>;

    /// Find a [`UserRecoveryTicket`] by its ticket
    ///
    /// Returns `None` if no [`UserRecoveryTicket`] was found
    ///
    /// # Parameters
    ///
    /// * `ticket`: The ticket of the [`UserRecoveryTicket`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_ticket(
        &mut self,
        ticket: &str,
    ) -> Result<Option<UserRecoveryTicket>, Self::Error>;

    /// Add a [`UserRecoveryTicket`] to the given [`UserRecoverySession`] for
    /// the given [`UserEmail`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `session`: The [`UserRecoverySession`] to add the ticket to
    /// * `user_email`: The [`UserEmail`] to add the ticket for
    /// * `ticket`: The ticket to add
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add_ticket(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_recovery_session: &UserRecoverySession,
        user_email: &UserEmail,
        ticket: String,
    ) -> Result<UserRecoveryTicket, Self::Error>;

    /// Consume a [`UserRecoveryTicket`] and mark the session as used
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock to use to record the time of consumption
    /// * `ticket`: The [`UserRecoveryTicket`] to consume
    /// * `session`: The [`UserRecoverySession`] to mark as used
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails or if the
    /// recovery session was already used
    async fn consume_ticket(
        &mut self,
        clock: &dyn Clock,
        user_recovery_ticket: UserRecoveryTicket,
        user_recovery_session: UserRecoverySession,
    ) -> Result<UserRecoverySession, Self::Error>;
}

repository_impl!(UserRecoveryRepository:
    async fn lookup_session(&mut self, id: Ulid) -> Result<Option<UserRecoverySession>, Self::Error>;

    async fn add_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        user_agent: String,
        ip_address: Option<IpAddr>,
        locale: String,
    ) -> Result<UserRecoverySession, Self::Error>;

    async fn find_ticket(
        &mut self,
        ticket: &str,
    ) -> Result<Option<UserRecoveryTicket>, Self::Error>;

    async fn add_ticket(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_recovery_session: &UserRecoverySession,
        user_email: &UserEmail,
        ticket: String,
    ) -> Result<UserRecoveryTicket, Self::Error>;

    async fn consume_ticket(
        &mut self,
        clock: &dyn Clock,
        user_recovery_ticket: UserRecoveryTicket,
        user_recovery_session: UserRecoverySession,
    ) -> Result<UserRecoverySession, Self::Error>;
);
