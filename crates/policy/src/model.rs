// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Input and output types for policy evaluation.
//!
//! This is useful to generate JSON schemas for each input type, which can then
//! be type-checked by Open Policy Agent.

use std::net::IpAddr;

use mas_data_model::{Client, User};
use oauth2_types::{registration::VerifiedClientMetadata, scope::Scope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A well-known policy code.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Code {
    /// The username is too short.
    UsernameTooShort,

    /// The username is too long.
    UsernameTooLong,

    /// The username contains invalid characters.
    UsernameInvalidChars,

    /// The username contains only numeric characters.
    UsernameAllNumeric,

    /// The username is banned.
    UsernameBanned,

    /// The username is not allowed.
    UsernameNotAllowed,

    /// The email domain is not allowed.
    EmailDomainNotAllowed,

    /// The email domain is banned.
    EmailDomainBanned,

    /// The email address is not allowed.
    EmailNotAllowed,

    /// The email address is banned.
    EmailBanned,

    /// The user has reached their session limit.
    TooManySessions,
}

impl Code {
    /// Returns the code as a string
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UsernameTooShort => "username-too-short",
            Self::UsernameTooLong => "username-too-long",
            Self::UsernameInvalidChars => "username-invalid-chars",
            Self::UsernameAllNumeric => "username-all-numeric",
            Self::UsernameBanned => "username-banned",
            Self::UsernameNotAllowed => "username-not-allowed",
            Self::EmailDomainNotAllowed => "email-domain-not-allowed",
            Self::EmailDomainBanned => "email-domain-banned",
            Self::EmailNotAllowed => "email-not-allowed",
            Self::EmailBanned => "email-banned",
            Self::TooManySessions => "too-many-sessions",
        }
    }
}

/// A single violation of a policy.
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct Violation {
    pub msg: String,
    pub redirect_uri: Option<String>,
    pub field: Option<String>,
    pub code: Option<Code>,
}

/// The result of a policy evaluation.
#[derive(Deserialize, Debug)]
pub struct EvaluationResult {
    #[serde(rename = "result")]
    pub violations: Vec<Violation>,
}

impl std::fmt::Display for EvaluationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for violation in &self.violations {
            if first {
                first = false;
            } else {
                write!(f, ", ")?;
            }
            write!(f, "{}", violation.msg)?;
        }
        Ok(())
    }
}

impl EvaluationResult {
    /// Returns true if the policy evaluation was successful.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Identity of the requester
#[derive(Serialize, Debug, Default, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Requester {
    /// IP address of the entity making the request
    pub ip_address: Option<IpAddr>,

    /// User agent of the entity making the request
    pub user_agent: Option<String>,
}

#[derive(Serialize, Debug, JsonSchema)]
pub enum RegistrationMethod {
    #[serde(rename = "password")]
    Password,

    #[serde(rename = "upstream-oauth2")]
    UpstreamOAuth2,
}

/// Input for the user registration policy.
#[derive(Serialize, Debug, JsonSchema)]
#[serde(tag = "registration_method")]
pub struct RegisterInput<'a> {
    pub registration_method: RegistrationMethod,

    pub username: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<&'a str>,

    pub requester: Requester,
}

/// Input for the client registration policy.
#[derive(Serialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ClientRegistrationInput<'a> {
    #[schemars(with = "std::collections::HashMap<String, serde_json::Value>")]
    pub client_metadata: &'a VerifiedClientMetadata,
    pub requester: Requester,
}

#[derive(Serialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:token-exchange")]
    TokenExchange,
}

/// Information about an upstream OAuth 2.0 provider.
/// Only populated for token exchange grants.
#[derive(Serialize, Debug, JsonSchema)]
pub struct UpstreamProviderInfo<'a> {
    pub id: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_name: Option<&'a str>,
}

/// Input for the authorization grant policy.
#[derive(Serialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct AuthorizationGrantInput<'a> {
    #[schemars(with = "Option<std::collections::HashMap<String, serde_json::Value>>")]
    pub user: Option<&'a User>,

    /// How many sessions the user has.
    /// Not populated if it's not a user logging in.
    pub session_counts: Option<SessionCounts>,

    #[schemars(with = "std::collections::HashMap<String, serde_json::Value>")]
    pub client: &'a Client,

    #[schemars(with = "String")]
    pub scope: &'a Scope,

    pub grant_type: GrantType,

    /// Information about the upstream provider being targeted.
    /// Only populated for token exchange grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_provider: Option<UpstreamProviderInfo<'a>>,

    pub requester: Requester,
}

/// Input for the compatibility login policy.
#[derive(Serialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct CompatLoginInput<'a> {
    #[schemars(with = "std::collections::HashMap<String, serde_json::Value>")]
    pub user: &'a User,

    /// How many sessions the user has.
    pub session_counts: SessionCounts,

    /// Whether a session will be replaced by this login
    pub session_replaced: bool,

    /// What type of login is being performed.
    /// This also determines whether the login is interactive.
    pub login: CompatLogin,

    pub requester: Requester,
}

#[derive(Serialize, Debug, JsonSchema)]
#[serde(tag = "type")]
pub enum CompatLogin {
    /// Used as the interactive part of SSO login.
    #[serde(rename = "m.login.sso")]
    Sso { redirect_uri: String },

    /// Used as the final (non-interactive) stage of SSO login.
    #[serde(rename = "m.login.token")]
    Token,

    /// Non-interactive password-over-the-API login.
    #[serde(rename = "m.login.password")]
    Password,
}

/// Information about how many sessions the user has
#[derive(Serialize, Debug, JsonSchema)]
pub struct SessionCounts {
    pub total: u64,

    pub oauth2: u64,
    pub compat: u64,
    pub personal: u64,
}

/// Input for the email add policy.
#[derive(Serialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct EmailInput<'a> {
    pub email: &'a str,

    pub requester: Requester,
}
