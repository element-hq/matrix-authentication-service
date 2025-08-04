// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Repositories to interact with entities of the compatibility layer

mod access_token;
mod refresh_token;
mod session;
mod sso_login;

pub use self::{
    access_token::CompatAccessTokenRepository,
    refresh_token::CompatRefreshTokenRepository,
    session::{CompatSessionFilter, CompatSessionRepository},
    sso_login::{CompatSsoLoginFilter, CompatSsoLoginRepository},
};
