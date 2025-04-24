// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use mas_data_model::{UserEmailAuthentication, UserRegistration};
use rand_core::RngCore;
use ulid::Ulid;
use url::Url;

use crate::{Clock, repository_impl};

/// A [`UserRegistrationRepository`] helps interacting with [`UserRegistration`]
/// saved in the storage backend
#[async_trait]
pub trait UserRegistrationRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`UserRegistration`] by its ID
    ///
    /// Returns `None` if no [`UserRegistration`] was found
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserRegistration`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserRegistration>, Self::Error>;

    /// Create a new [`UserRegistration`] session
    ///
    /// Returns the newly created [`UserRegistration`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `username`: The username of the user
    /// * `ip_address`: The IP address of the user agent, if any
    /// * `user_agent`: The user agent of the user agent, if any
    /// * `post_auth_action`: The post auth action to execute after the
    ///   registration, if any
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        post_auth_action: Option<serde_json::Value>,
    ) -> Result<UserRegistration, Self::Error>;

    /// Set the display name of a [`UserRegistration`]
    ///
    /// Returns the updated [`UserRegistration`]
    ///
    /// # Parameters
    ///
    /// * `user_registration`: The [`UserRegistration`] to update
    /// * `display_name`: The display name to set
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails or if the
    /// registration is already completed
    async fn set_display_name(
        &mut self,
        user_registration: UserRegistration,
        display_name: String,
    ) -> Result<UserRegistration, Self::Error>;

    /// Set the terms URL of a [`UserRegistration`]
    ///
    /// Returns the updated [`UserRegistration`]
    ///
    /// # Parameters
    ///
    /// * `user_registration`: The [`UserRegistration`] to update
    /// * `terms_url`: The terms URL to set
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails or if the
    /// registration is already completed
    async fn set_terms_url(
        &mut self,
        user_registration: UserRegistration,
        terms_url: Url,
    ) -> Result<UserRegistration, Self::Error>;

    /// Set the email authentication code of a [`UserRegistration`]
    ///
    /// Returns the updated [`UserRegistration`]
    ///
    /// # Parameters
    ///
    /// * `user_registration`: The [`UserRegistration`] to update
    /// * `email_authentication`: The [`UserEmailAuthentication`] to set
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails or if the
    /// registration is already completed
    async fn set_email_authentication(
        &mut self,
        user_registration: UserRegistration,
        email_authentication: &UserEmailAuthentication,
    ) -> Result<UserRegistration, Self::Error>;

    /// Set the password of a [`UserRegistration`]
    ///
    /// Returns the updated [`UserRegistration`]
    ///
    /// # Parameters
    ///
    /// * `user_registration`: The [`UserRegistration`] to update
    /// * `hashed_password`: The hashed password to set
    /// * `version`: The version of the hashing scheme
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails or if the
    /// registration is already completed
    async fn set_password(
        &mut self,
        user_registration: UserRegistration,
        hashed_password: String,
        version: u16,
    ) -> Result<UserRegistration, Self::Error>;

    /// Complete a [`UserRegistration`]
    ///
    /// Returns the updated [`UserRegistration`]
    ///
    /// # Parameters
    ///
    /// * `clock`: The clock used to generate timestamps
    /// * `user_registration`: The [`UserRegistration`] to complete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails or if the
    /// registration is already completed
    async fn complete(
        &mut self,
        clock: &dyn Clock,
        user_registration: UserRegistration,
    ) -> Result<UserRegistration, Self::Error>;
}

repository_impl!(UserRegistrationRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserRegistration>, Self::Error>;
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        username: String,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        post_auth_action: Option<serde_json::Value>,
    ) -> Result<UserRegistration, Self::Error>;
    async fn set_display_name(
        &mut self,
        user_registration: UserRegistration,
        display_name: String,
    ) -> Result<UserRegistration, Self::Error>;
    async fn set_terms_url(
        &mut self,
        user_registration: UserRegistration,
        terms_url: Url,
    ) -> Result<UserRegistration, Self::Error>;
    async fn set_email_authentication(
        &mut self,
        user_registration: UserRegistration,
        email_authentication: &UserEmailAuthentication,
    ) -> Result<UserRegistration, Self::Error>;
    async fn set_password(
        &mut self,
        user_registration: UserRegistration,
        hashed_password: String,
        version: u16,
    ) -> Result<UserRegistration, Self::Error>;
    async fn complete(
        &mut self,
        clock: &dyn Clock,
        user_registration: UserRegistration,
    ) -> Result<UserRegistration, Self::Error>;
);
