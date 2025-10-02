// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Repositories to deal with Personal Sessions and Personal Access Tokens
//! (PATs), which are sessions/access tokens created manually by users for use
//! in scripts, bots and similar applications.

mod access_token;
mod session;

pub use self::{access_token::PersonalAccessTokenRepository, session::PersonalSessionRepository};
