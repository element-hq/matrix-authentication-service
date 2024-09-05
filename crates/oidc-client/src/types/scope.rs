// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Helpers types to use scopes.

use std::{fmt, str::FromStr};

use oauth2_types::scope::ScopeToken as StrScopeToken;
pub use oauth2_types::scope::{InvalidScope, Scope};

use crate::PrivString;

/// Tokens to define the scope of an access token or to request specific claims.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeToken {
    /// `openid`
    ///
    /// Required for OpenID Connect requests.
    Openid,

    /// `profile`
    ///
    /// Requests access to the end-user's profile.
    Profile,

    /// `email`
    ///
    /// Requests access to the end-user's email address.
    Email,

    /// `address`
    ///
    /// Requests access to the end-user's address.
    Address,

    /// `phone`
    ///
    /// Requests access to the end-user's phone number.
    Phone,

    /// `offline_access`
    ///
    /// Requests that an OAuth 2.0 refresh token be issued that can be used to
    /// obtain an access token that grants access to the end-user's `UserInfo`
    /// Endpoint even when the end-user is not present (not logged in).
    OfflineAccess,

    /// `urn:matrix:org.matrix.msc2967.client:api:{token}`
    ///
    /// Requests access to the Matrix Client-Server API.
    MatrixApi(MatrixApiScopeToken),

    /// `urn:matrix:org.matrix.msc2967.client:device:{device_id}`
    ///
    /// Requests access to the Matrix device with the given `device_id`.
    ///
    /// To access the device ID, use [`ScopeToken::matrix_device_id`].
    MatrixDevice(PrivString),

    /// Another scope token.
    ///
    /// To access it's value use this type's `Display` implementation.
    Custom(PrivString),
}

impl ScopeToken {
    /// Creates a Matrix device scope token with the given device ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the device ID string is not compatible with the
    /// scope syntax.
    pub fn try_with_matrix_device(device_id: String) -> Result<Self, InvalidScope> {
        // Check that the device ID is compatible with the scope format.
        StrScopeToken::from_str(&device_id)?;

        Ok(Self::MatrixDevice(PrivString(device_id)))
    }

    /// Get the device ID of this scope token, if it is a
    /// [`ScopeToken::MatrixDevice`].
    #[must_use]
    pub fn matrix_device_id(&self) -> Option<&str> {
        match &self {
            Self::MatrixDevice(id) => Some(&id.0),
            _ => None,
        }
    }
}

impl fmt::Display for ScopeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeToken::Openid => write!(f, "openid"),
            ScopeToken::Profile => write!(f, "profile"),
            ScopeToken::Email => write!(f, "email"),
            ScopeToken::Address => write!(f, "address"),
            ScopeToken::Phone => write!(f, "phone"),
            ScopeToken::OfflineAccess => write!(f, "offline_access"),
            ScopeToken::MatrixApi(scope) => {
                write!(f, "urn:matrix:org.matrix.msc2967.client:api:{scope}")
            }
            ScopeToken::MatrixDevice(s) => {
                write!(f, "urn:matrix:org.matrix.msc2967.client:device:{}", s.0)
            }
            ScopeToken::Custom(s) => f.write_str(&s.0),
        }
    }
}

impl From<StrScopeToken> for ScopeToken {
    fn from(t: StrScopeToken) -> Self {
        match &*t {
            "openid" => Self::Openid,
            "profile" => Self::Profile,
            "email" => Self::Email,
            "address" => Self::Address,
            "phone" => Self::Phone,
            "offline_access" => Self::OfflineAccess,
            s => {
                if let Some(matrix_scope) =
                    s.strip_prefix("urn:matrix:org.matrix.msc2967.client:api:")
                {
                    Self::MatrixApi(
                        MatrixApiScopeToken::from_str(matrix_scope)
                            .expect("If the whole string is a valid scope, a substring is too"),
                    )
                } else if let Some(device_id) =
                    s.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:")
                {
                    Self::MatrixDevice(PrivString(device_id.to_owned()))
                } else {
                    Self::Custom(PrivString(s.to_owned()))
                }
            }
        }
    }
}

impl From<ScopeToken> for StrScopeToken {
    fn from(t: ScopeToken) -> Self {
        let s = t.to_string();
        match StrScopeToken::from_str(&s) {
            Ok(t) => t,
            Err(_) => unreachable!(),
        }
    }
}

impl FromStr for ScopeToken {
    type Err = InvalidScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = StrScopeToken::from_str(s)?;
        Ok(t.into())
    }
}

/// Helpers for [`Scope`] to work with [`ScopeToken`].
pub trait ScopeExt {
    /// Insert the given `ScopeToken` into this `Scope`.
    fn insert_token(&mut self, token: ScopeToken) -> bool;

    /// Whether this `Scope` contains the given `ScopeToken`.
    fn contains_token(&self, token: &ScopeToken) -> bool;
}

impl ScopeExt for Scope {
    fn insert_token(&mut self, token: ScopeToken) -> bool {
        self.insert(token.into())
    }

    fn contains_token(&self, token: &ScopeToken) -> bool {
        self.contains(&token.to_string())
    }
}

impl FromIterator<ScopeToken> for Scope {
    fn from_iter<T: IntoIterator<Item = ScopeToken>>(iter: T) -> Self {
        iter.into_iter().map(Into::<StrScopeToken>::into).collect()
    }
}

/// Tokens to define the scope of an access to the Matrix Client-Server API.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatrixApiScopeToken {
    /// `*`
    ///
    /// Access the full Client-Server API.
    Full,

    /// `guest`
    ///
    /// Access the Client-Server API as a guest.
    Guest,

    /// Another scope token.
    ///
    /// To access it's value use this type's `Display` implementation.
    Custom(PrivString),
}

impl fmt::Display for MatrixApiScopeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "*"),
            Self::Guest => write!(f, "guest"),
            Self::Custom(s) => f.write_str(&s.0),
        }
    }
}

impl FromStr for MatrixApiScopeToken {
    type Err = InvalidScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Check that it's a valid scope string.
        StrScopeToken::from_str(s)?;

        let t = match s {
            "*" => Self::Full,
            "guest" => Self::Guest,
            _ => Self::Custom(PrivString(s.to_owned())),
        };
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn parse_scope_token() {
        assert_eq!(ScopeToken::from_str("openid"), Ok(ScopeToken::Openid));

        let scope =
            ScopeToken::from_str("urn:matrix:org.matrix.msc2967.client:device:ABCDEFGHIJKL")
                .unwrap();
        assert_matches!(scope, ScopeToken::MatrixDevice(_));
        assert_eq!(scope.matrix_device_id(), Some("ABCDEFGHIJKL"));

        let scope = ScopeToken::from_str("urn:matrix:org.matrix.msc2967.client:api:*").unwrap();
        assert_eq!(scope, ScopeToken::MatrixApi(MatrixApiScopeToken::Full));

        let scope = ScopeToken::from_str("urn:matrix:org.matrix.msc2967.client:api:guest").unwrap();
        assert_eq!(scope, ScopeToken::MatrixApi(MatrixApiScopeToken::Guest));

        let scope =
            ScopeToken::from_str("urn:matrix:org.matrix.msc2967.client:api:my.custom.scope")
                .unwrap();
        let api_scope = assert_matches!(scope, ScopeToken::MatrixApi(s) => s);
        assert_matches!(api_scope, MatrixApiScopeToken::Custom(_));
        assert_eq!(api_scope.to_string(), "my.custom.scope");

        assert_eq!(ScopeToken::from_str("invalid\\scope"), Err(InvalidScope));
        assert_eq!(
            MatrixApiScopeToken::from_str("invalid\\scope"),
            Err(InvalidScope)
        );
    }

    #[test]
    fn display_scope_token() {
        let scope = ScopeToken::MatrixApi(MatrixApiScopeToken::Full);
        assert_eq!(
            scope.to_string(),
            "urn:matrix:org.matrix.msc2967.client:api:*"
        );

        let scope = ScopeToken::MatrixApi(MatrixApiScopeToken::Guest);
        assert_eq!(
            scope.to_string(),
            "urn:matrix:org.matrix.msc2967.client:api:guest"
        );

        let api_scope = MatrixApiScopeToken::from_str("my.custom.scope").unwrap();
        let scope = ScopeToken::MatrixApi(api_scope);
        assert_eq!(
            scope.to_string(),
            "urn:matrix:org.matrix.msc2967.client:api:my.custom.scope"
        );
    }

    #[test]
    fn parse_scope() {
        let scope = Scope::from_str("openid profile address").unwrap();
        assert_eq!(scope.len(), 3);
        assert!(scope.contains_token(&ScopeToken::Openid));
        assert!(scope.contains_token(&ScopeToken::Profile));
        assert!(scope.contains_token(&ScopeToken::Address));
        assert!(!scope.contains_token(&ScopeToken::OfflineAccess));
    }

    #[test]
    fn display_scope() {
        let mut scope: Scope = [ScopeToken::Profile].into_iter().collect();
        assert_eq!(scope.to_string(), "profile");

        scope.insert_token(ScopeToken::MatrixApi(MatrixApiScopeToken::Full));
        assert_eq!(
            scope.to_string(),
            "profile urn:matrix:org.matrix.msc2967.client:api:*"
        );
    }
}
