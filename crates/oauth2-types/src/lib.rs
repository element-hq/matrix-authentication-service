// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! [OAuth 2.0] and [OpenID Connect] types.
//!
//! This is part of the [Matrix Authentication Service] project.
//!
//! [OAuth 2.0]: https://oauth.net/2/
//! [OpenID Connect]: https://openid.net/connect/
//! [Matrix Authentication Service]: https://github.com/element-hq/matrix-authentication-service

#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]

pub mod errors;
pub mod oidc;
pub mod pkce;
pub mod registration;
pub mod requests;
pub mod response_type;
pub mod scope;
pub mod webfinger;

/// Traits intended for blanket imports.
pub mod prelude {
    pub use crate::pkce::CodeChallengeMethodExt;
}

#[cfg(test)]
mod test_utils;
