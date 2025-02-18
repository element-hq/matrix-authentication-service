// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use mas_data_model::SiteConfig;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng, RepositoryError};

use crate::{graphql::Requester, passwords::PasswordManager, Limiter};

#[async_trait::async_trait]
pub trait State {
    async fn repository(&self) -> Result<BoxRepository, RepositoryError>;
    async fn policy(&self) -> Result<Policy, mas_policy::InstantiateError>;
    fn password_manager(&self) -> PasswordManager;
    fn homeserver_connection(&self) -> &dyn HomeserverConnection<Error = anyhow::Error>;
    fn clock(&self) -> BoxClock;
    fn rng(&self) -> BoxRng;
    fn site_config(&self) -> &SiteConfig;
    fn url_builder(&self) -> &UrlBuilder;
    fn limiter(&self) -> &Limiter;
}

pub type BoxState = Box<dyn State + Send + Sync + 'static>;

pub trait ContextExt {
    fn state(&self) -> &BoxState;

    fn requester(&self) -> &Requester;
}

impl ContextExt for async_graphql::Context<'_> {
    fn state(&self) -> &BoxState {
        self.data_unchecked()
    }

    fn requester(&self) -> &Requester {
        self.data_unchecked()
    }
}
