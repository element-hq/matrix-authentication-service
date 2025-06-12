// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! OAuth 2.0 and OpenID Connect types.

pub mod client_credentials;

use std::collections::HashMap;

#[doc(inline)]
pub use mas_iana as iana;
use mas_jose::jwt::Jwt;
pub use oauth2_types::*;
use serde_json::Value;

/// An OpenID Connect [ID Token].
///
/// [ID Token]: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
pub type IdToken<'a> = Jwt<'a, HashMap<String, Value>>;
