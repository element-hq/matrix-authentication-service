// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Types to define an [access token's scope].
//!
//! [access token's scope]: https://www.rfc-editor.org/rfc/rfc6749#section-3.3

#![allow(clippy::module_name_repetitions)]

use std::{
    borrow::Cow,
    collections::BTreeSet,
    iter::FromIterator,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The error type returned when a scope is invalid.
#[derive(Debug, Error, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[error("Invalid scope format")]
pub struct InvalidScope;

/// A scope token or scope value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeToken(Cow<'static, str>);

impl ScopeToken {
    /// Create a `ScopeToken` from a static string. The validity of it is not
    /// checked since it has to be valid in const contexts
    #[must_use]
    pub const fn from_static(token: &'static str) -> Self {
        Self(Cow::Borrowed(token))
    }

    /// Get the scope token as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

/// `openid`.
///
/// Must be included in OpenID Connect requests.
pub const OPENID: ScopeToken = ScopeToken::from_static("openid");

/// `profile`.
///
/// Requests access to the End-User's default profile Claims.
pub const PROFILE: ScopeToken = ScopeToken::from_static("profile");

/// `email`.
///
/// Requests access to the `email` and `email_verified` Claims.
pub const EMAIL: ScopeToken = ScopeToken::from_static("email");

/// `address`.
///
/// Requests access to the `address` Claim.
pub const ADDRESS: ScopeToken = ScopeToken::from_static("address");

/// `phone`.
///
/// Requests access to the `phone_number` and `phone_number_verified` Claims.
pub const PHONE: ScopeToken = ScopeToken::from_static("phone");

/// `offline_access`.
///
/// Requests that an OAuth 2.0 Refresh Token be issued that can be used to
/// obtain an Access Token that grants access to the End-User's Userinfo
/// Endpoint even when the End-User is not present (not logged in).
pub const OFFLINE_ACCESS: ScopeToken = ScopeToken::from_static("offline_access");

// As per RFC6749 appendix A:
// https://datatracker.ietf.org/doc/html/rfc6749#appendix-A
//
//    NQCHAR     = %x21 / %x23-5B / %x5D-7E
fn nqchar(c: char) -> bool {
    '\x21' == c || ('\x23'..'\x5B').contains(&c) || ('\x5D'..'\x7E').contains(&c)
}

impl FromStr for ScopeToken {
    type Err = InvalidScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // As per RFC6749 appendix A.4:
        // https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.4
        //
        //    scope-token = 1*NQCHAR
        if !s.is_empty() && s.chars().all(nqchar) {
            Ok(ScopeToken(Cow::Owned(s.into())))
        } else {
            Err(InvalidScope)
        }
    }
}

impl Deref for ScopeToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for ScopeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope(BTreeSet<ScopeToken>);

impl Deref for Scope {
    type Target = BTreeSet<ScopeToken>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Scope {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromStr for Scope {
    type Err = InvalidScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // As per RFC6749 appendix A.4:
        // https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.4
        //
        //    scope       = scope-token *( SP scope-token )
        let scopes: Result<BTreeSet<ScopeToken>, InvalidScope> =
            s.split(' ').map(ScopeToken::from_str).collect();

        Ok(Self(scopes?))
    }
}

impl Scope {
    /// Whether this `Scope` is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        // This should never be the case?
        self.0.is_empty()
    }

    /// The number of tokens in the `Scope`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this `Scope` contains the given value.
    #[must_use]
    pub fn contains(&self, token: &str) -> bool {
        ScopeToken::from_str(token)
            .map(|token| self.0.contains(&token))
            .unwrap_or(false)
    }

    /// Inserts the given token in this `Scope`.
    ///
    /// Returns whether the token was newly inserted.
    pub fn insert(&mut self, value: ScopeToken) -> bool {
        self.0.insert(value)
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, token) in self.0.iter().enumerate() {
            if index == 0 {
                write!(f, "{token}")?;
            } else {
                write!(f, " {token}")?;
            }
        }

        Ok(())
    }
}

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // FIXME: seems like there is an unnecessary clone here?
        let scope: String = Deserialize::deserialize(deserializer)?;
        Scope::from_str(&scope).map_err(serde::de::Error::custom)
    }
}

impl FromIterator<ScopeToken> for Scope {
    fn from_iter<T: IntoIterator<Item = ScopeToken>>(iter: T) -> Self {
        Self(BTreeSet::from_iter(iter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_token() {
        assert_eq!(ScopeToken::from_str("openid"), Ok(OPENID));

        assert_eq!(ScopeToken::from_str("invalid\\scope"), Err(InvalidScope));
    }

    #[test]
    fn parse_scope() {
        let scope = Scope::from_str("openid profile address").unwrap();
        assert_eq!(scope.len(), 3);
        assert!(scope.contains("openid"));
        assert!(scope.contains("profile"));
        assert!(scope.contains("address"));
        assert!(!scope.contains("unknown"));

        assert!(
            Scope::from_str("").is_err(),
            "there should always be at least one token in the scope"
        );

        assert!(Scope::from_str("invalid\\scope").is_err());
        assert!(Scope::from_str("no  double space").is_err());
        assert!(Scope::from_str(" no leading space").is_err());
        assert!(Scope::from_str("no trailing space ").is_err());

        let scope = Scope::from_str("openid").unwrap();
        assert_eq!(scope.len(), 1);
        assert!(scope.contains("openid"));
        assert!(!scope.contains("profile"));
        assert!(!scope.contains("address"));

        assert_eq!(
            Scope::from_str("order does not matter"),
            Scope::from_str("matter not order does"),
        );

        assert!(Scope::from_str("http://example.com").is_ok());
        assert!(Scope::from_str("urn:matrix:client:api:*").is_ok());
        assert!(Scope::from_str("urn:matrix:org.matrix.msc2967.client:api:*").is_ok());
    }
}
