// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! An [OpenID Connect] client library for the [Matrix] specification.
//!
//! This is part of the [Matrix Authentication Service] project.
//!
//! # Scope
//!
//! The scope of this crate is to support OIDC features required by the
//! Matrix specification according to [MSC3861] and its sub-proposals.
//!
//! As such, it is compatible with the OpenID Connect 1.0 specification, but
//! also enforces Matrix-specific requirements or adds compatibility with new
//! [OAuth 2.0] features.
//!
//! # OpenID Connect and OAuth 2.0 Features
//!
//! - Grant Types:
//!   - [Authorization Code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
//!   - [Client Credentials](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
//!   - [Device Code](https://www.rfc-editor.org/rfc/rfc8628) (TBD)
//!   - [Refresh Token](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens)
//! - [User Info](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
//! - [PKCE](https://www.rfc-editor.org/rfc/rfc7636)
//!
//! # Matrix features
//!
//! - Client registration
//! - Login
//! - Matrix API Scopes
//! - Logout
//!
//! [OpenID Connect]: https://openid.net/connect/
//! [Matrix]: https://matrix.org/
//! [Matrix Authentication Service]: https://github.com/element-hq/matrix-authentication-service
//! [MSC3861]: https://github.com/matrix-org/matrix-spec-proposals/pull/3861
//! [OAuth 2.0]: https://oauth.net/2/

#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions, clippy::implicit_hasher)]

pub mod error;
pub mod requests;
pub mod types;

use std::fmt;

#[doc(inline)]
pub use mas_jose as jose;

// Wrapper around `String` that cannot be used in a meaningful way outside of
// this crate. Used for string enums that only allow certain characters because
// their variant can't be private.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivString(String);

impl fmt::Debug for PrivString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
