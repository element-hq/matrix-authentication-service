// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_graphql::{Response, ServerError};
use mas_data_model::SiteConfig;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng, RepositoryError};

use crate::{Limiter, graphql::Requester, passwords::PasswordManager};

const CLEAR_SESSION_SENTINEL: &str = "__CLEAR_SESSION__";

#[async_trait::async_trait]
pub trait State {
    async fn repository(&self) -> Result<BoxRepository, RepositoryError>;
    async fn policy(&self) -> Result<Policy, mas_policy::InstantiateError>;
    fn password_manager(&self) -> PasswordManager;
    fn homeserver_connection(&self) -> &dyn HomeserverConnection;
    fn clock(&self) -> BoxClock;
    fn rng(&self) -> BoxRng;
    fn site_config(&self) -> &SiteConfig;
    fn url_builder(&self) -> &UrlBuilder;
    fn limiter(&self) -> &Limiter;
}

pub type BoxState = Box<dyn State + Send + Sync + 'static>;

pub trait ContextExt {
    fn state(&self) -> &BoxState;

    fn mark_session_ended(&self);

    fn requester(&self) -> &Requester;
}

impl ContextExt for async_graphql::Context<'_> {
    fn state(&self) -> &BoxState {
        self.data_unchecked()
    }

    fn mark_session_ended(&self) {
        // Add a sentinel to the error context, so that we can know that we need to
        // clear the session
        // XXX: this is a bit of a hack, but the only sane way to get infos from within
        // a mutation up to the HTTP handler
        self.add_error(ServerError::new(CLEAR_SESSION_SENTINEL, None));
    }

    fn requester(&self) -> &Requester {
        self.data_unchecked()
    }
}

/// Returns true if the response contains a sentinel error indicating that the
/// current cookie session has ended, and the session cookie should be cleared.
///
/// Also removes the sentinel error from the response.
pub fn has_session_ended(response: &mut Response) -> bool {
    let errors = std::mem::take(&mut response.errors);
    let mut must_clear_session = false;
    for error in errors {
        if error.message == CLEAR_SESSION_SENTINEL {
            must_clear_session = true;
        } else {
            response.errors.push(error);
        }
    }
    must_clear_session
}
