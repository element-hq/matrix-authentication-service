// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{Clock, User};
use rand_core::RngCore;
use url::Url;

use crate::repository_impl;

/// A [`UserTermsRepository`] helps interacting with the terms of service agreed
/// by a [`User`]
#[async_trait]
pub trait UserTermsRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Accept the terms of service by a [`User`]
    ///
    /// # Parameters
    ///
    /// * `rng`: A random number generator used to generate IDs
    /// * `clock`: The clock used to generate timestamps
    /// * `user`: The [`User`] accepting the terms
    /// * `terms_url`: The URL of the terms of service the user is accepting
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn accept_terms(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        terms_url: Url,
    ) -> Result<(), Self::Error>;
}

repository_impl!(UserTermsRepository:
    async fn accept_terms(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        terms_url: Url,
    ) -> Result<(), Self::Error>;
);
