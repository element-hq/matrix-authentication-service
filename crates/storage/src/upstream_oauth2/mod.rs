// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Repositories to interact with entities related to the upstream OAuth 2.0
//! providers

mod link;
mod link_token;
mod provider;
mod session;

pub use self::{
    link::{UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository},
    link_token::UpstreamOAuthLinkTokenRepository,
    provider::{
        UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
    },
    session::{UpstreamOAuthSessionFilter, UpstreamOAuthSessionRepository},
};
