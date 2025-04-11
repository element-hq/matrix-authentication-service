// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use chrono::{DateTime, Utc};
use mas_iana::jose::JsonWebSignatureAlg;
use oauth2_types::scope::Scope;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    /// Use OIDC discovery to fetch and verify the provider metadata
    #[default]
    Oidc,

    /// Use OIDC discovery to fetch the provider metadata, but don't verify it
    Insecure,

    /// Don't fetch the provider metadata
    Disabled,
}

impl DiscoveryMode {
    /// Returns `true` if discovery is disabled
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        matches!(self, DiscoveryMode::Disabled)
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid discovery mode {0:?}")]
pub struct InvalidDiscoveryModeError(String);

impl std::str::FromStr for DiscoveryMode {
    type Err = InvalidDiscoveryModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oidc" => Ok(Self::Oidc),
            "insecure" => Ok(Self::Insecure),
            "disabled" => Ok(Self::Disabled),
            s => Err(InvalidDiscoveryModeError(s.to_owned())),
        }
    }
}

impl DiscoveryMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Insecure => "insecure",
            Self::Disabled => "disabled",
        }
    }
}

impl std::fmt::Display for DiscoveryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PkceMode {
    /// Use PKCE if the provider supports it
    #[default]
    Auto,

    /// Always use PKCE with the S256 method
    S256,

    /// Don't use PKCE
    Disabled,
}

#[derive(Debug, Clone, Error)]
#[error("Invalid PKCE mode {0:?}")]
pub struct InvalidPkceModeError(String);

impl std::str::FromStr for PkceMode {
    type Err = InvalidPkceModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "s256" => Ok(Self::S256),
            "disabled" => Ok(Self::Disabled),
            s => Err(InvalidPkceModeError(s.to_owned())),
        }
    }
}

impl PkceMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::S256 => "s256",
            Self::Disabled => "disabled",
        }
    }
}

impl std::fmt::Display for PkceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid response mode {0:?}")]
pub struct InvalidResponseModeError(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    #[default]
    Query,
    FormPost,
}

impl From<ResponseMode> for oauth2_types::requests::ResponseMode {
    fn from(value: ResponseMode) -> Self {
        match value {
            ResponseMode::Query => oauth2_types::requests::ResponseMode::Query,
            ResponseMode::FormPost => oauth2_types::requests::ResponseMode::FormPost,
        }
    }
}

impl ResponseMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::FormPost => "form_post",
        }
    }
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ResponseMode {
    type Err = InvalidResponseModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "query" => Ok(ResponseMode::Query),
            "form_post" => Ok(ResponseMode::FormPost),
            s => Err(InvalidResponseModeError(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
    ClientSecretJwt,
    PrivateKeyJwt,
    SignInWithApple,
}

impl TokenAuthMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretJwt => "client_secret_jwt",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::SignInWithApple => "sign_in_with_apple",
        }
    }
}

impl std::fmt::Display for TokenAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TokenAuthMethod {
    type Err = InvalidUpstreamOAuth2TokenAuthMethod;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_jwt" => Ok(Self::ClientSecretJwt),
            "private_key_jwt" => Ok(Self::PrivateKeyJwt),
            "sign_in_with_apple" => Ok(Self::SignInWithApple),
            s => Err(InvalidUpstreamOAuth2TokenAuthMethod(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Error)]
#[error("Invalid upstream OAuth 2.0 token auth method: {0}")]
pub struct InvalidUpstreamOAuth2TokenAuthMethod(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthProvider {
    pub id: Ulid,
    pub issuer: Option<String>,
    pub human_name: Option<String>,
    pub brand_name: Option<String>,
    pub discovery_mode: DiscoveryMode,
    pub pkce_mode: PkceMode,
    pub jwks_uri_override: Option<Url>,
    pub authorization_endpoint_override: Option<Url>,
    pub scope: Scope,
    pub token_endpoint_override: Option<Url>,
    pub userinfo_endpoint_override: Option<Url>,
    pub fetch_userinfo: bool,
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
    pub client_id: String,
    pub encrypted_client_secret: Option<String>,
    pub token_endpoint_signing_alg: Option<JsonWebSignatureAlg>,
    pub token_endpoint_auth_method: TokenAuthMethod,
    pub id_token_signed_response_alg: JsonWebSignatureAlg,
    pub response_mode: Option<ResponseMode>,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub claims_imports: ClaimsImports,
    pub allow_rp_initiated_logout: bool,
    pub end_session_endpoint_override: Option<Url>,
    pub additional_authorization_parameters: Vec<(String, String)>,
}

impl PartialOrd for UpstreamOAuthProvider {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.id.cmp(&other.id))
    }
}

impl Ord for UpstreamOAuthProvider {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl UpstreamOAuthProvider {
    /// Returns `true` if the provider is enabled
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.disabled_at.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClaimsImports {
    #[serde(default)]
    pub subject: SubjectPreference,

    #[serde(default)]
    pub localpart: ImportPreference,

    #[serde(default)]
    pub displayname: ImportPreference,

    #[serde(default)]
    pub email: ImportPreference,

    #[serde(default)]
    pub account_name: SubjectPreference,
}

// XXX: this should have another name
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SubjectPreference {
    #[serde(default)]
    pub template: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImportPreference {
    #[serde(default)]
    pub action: ImportAction,

    #[serde(default)]
    pub template: Option<String>,
}

impl std::ops::Deref for ImportPreference {
    type Target = ImportAction;

    fn deref(&self) -> &Self::Target {
        &self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ImportAction {
    /// Ignore the claim
    #[default]
    Ignore,

    /// Suggest the claim value, but allow the user to change it
    Suggest,

    /// Force the claim value, but don't fail if it is missing
    Force,

    /// Force the claim value, and fail if it is missing
    Require,
}

impl ImportAction {
    #[must_use]
    pub fn is_forced(&self) -> bool {
        matches!(self, Self::Force | Self::Require)
    }

    #[must_use]
    pub fn ignore(&self) -> bool {
        matches!(self, Self::Ignore)
    }

    #[must_use]
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Require)
    }

    #[must_use]
    pub fn should_import(&self, user_preference: bool) -> bool {
        match self {
            Self::Ignore => false,
            Self::Suggest => user_preference,
            Self::Force | Self::Require => true,
        }
    }
}
