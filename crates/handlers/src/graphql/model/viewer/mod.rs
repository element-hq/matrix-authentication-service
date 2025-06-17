// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::Union;

use crate::graphql::model::{BrowserSession, OAuth2Session, User};

mod anonymous;
pub use self::anonymous::Anonymous;

/// Represents the current viewer
#[derive(Union)]
pub enum Viewer {
    User(User),
    Anonymous(Anonymous),
}

impl Viewer {
    pub fn user(user: mas_data_model::User) -> Self {
        Self::User(User(user))
    }

    pub fn anonymous() -> Self {
        Self::Anonymous(Anonymous)
    }
}

/// Represents the current viewer's session
#[derive(Union)]
pub enum ViewerSession {
    BrowserSession(Box<BrowserSession>),
    OAuth2Session(Box<OAuth2Session>),
    Anonymous(Anonymous),
}

impl ViewerSession {
    pub fn browser_session(session: mas_data_model::BrowserSession) -> Self {
        Self::BrowserSession(Box::new(BrowserSession(session)))
    }

    pub fn oauth2_session(session: mas_data_model::Session) -> Self {
        Self::OAuth2Session(Box::new(OAuth2Session(session)))
    }

    pub fn anonymous() -> Self {
        Self::Anonymous(Anonymous)
    }
}
