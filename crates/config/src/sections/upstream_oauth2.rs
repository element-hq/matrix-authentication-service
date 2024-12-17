// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::collections::BTreeMap;

use mas_iana::jose::JsonWebSignatureAlg;
use schemars::JsonSchema;
use serde::{de::Error, Deserialize, Serialize};
use serde_with::skip_serializing_none;
use ulid::Ulid;
use url::Url;

use crate::ConfigurationSection;

/// Upstream OAuth 2.0 providers configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct UpstreamOAuth2Config {
    /// List of OAuth 2.0 providers
    pub providers: Vec<Provider>,
}

impl UpstreamOAuth2Config {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        self.providers.is_empty()
    }
}

impl ConfigurationSection for UpstreamOAuth2Config {
    const PATH: Option<&'static str> = Some("upstream_oauth2");

    fn validate(&self, figment: &figment::Figment) -> Result<(), figment::Error> {
        for (index, provider) in self.providers.iter().enumerate() {
            let annotate = |mut error: figment::Error| {
                error.metadata = figment
                    .find_metadata(&format!("{root}.providers", root = Self::PATH.unwrap()))
                    .cloned();
                error.profile = Some(figment::Profile::Default);
                error.path = vec![
                    Self::PATH.unwrap().to_owned(),
                    "providers".to_owned(),
                    index.to_string(),
                ];
                Err(error)
            };

            match provider.token_endpoint_auth_method {
                TokenAuthMethod::None
                | TokenAuthMethod::PrivateKeyJwt
                | TokenAuthMethod::SignInWithApple => {
                    if provider.client_secret.is_some() {
                        return annotate(figment::Error::custom("Unexpected field `client_secret` for the selected authentication method"));
                    }
                }
                TokenAuthMethod::ClientSecretBasic
                | TokenAuthMethod::ClientSecretPost
                | TokenAuthMethod::ClientSecretJwt => {
                    if provider.client_secret.is_none() {
                        return annotate(figment::Error::missing_field("client_secret"));
                    }
                }
            }

            match provider.token_endpoint_auth_method {
                TokenAuthMethod::None
                | TokenAuthMethod::ClientSecretBasic
                | TokenAuthMethod::ClientSecretPost
                | TokenAuthMethod::SignInWithApple => {
                    if provider.token_endpoint_auth_signing_alg.is_some() {
                        return annotate(figment::Error::custom(
                            "Unexpected field `token_endpoint_auth_signing_alg` for the selected authentication method",
                        ));
                    }
                }
                TokenAuthMethod::ClientSecretJwt | TokenAuthMethod::PrivateKeyJwt => {
                    if provider.token_endpoint_auth_signing_alg.is_none() {
                        return annotate(figment::Error::missing_field(
                            "token_endpoint_auth_signing_alg",
                        ));
                    }
                }
            }

            match provider.token_endpoint_auth_method {
                TokenAuthMethod::SignInWithApple => {
                    if provider.sign_in_with_apple.is_none() {
                        return annotate(figment::Error::missing_field("sign_in_with_apple"));
                    }
                }

                _ => {
                    if provider.sign_in_with_apple.is_some() {
                        return annotate(figment::Error::custom(
                            "Unexpected field `sign_in_with_apple` for the selected authentication method",
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// The response mode we ask the provider to use for the callback
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// `query`: The provider will send the response as a query string in the
    /// URL search parameters
    #[default]
    Query,

    /// `form_post`: The provider will send the response as a POST request with
    /// the response parameters in the request body
    ///
    /// <https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html>
    FormPost,
}

impl ResponseMode {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, ResponseMode::Query)
    }
}

/// Authentication methods used against the OAuth 2.0 provider
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuthMethod {
    /// `none`: No authentication
    None,

    /// `client_secret_basic`: `client_id` and `client_secret` used as basic
    /// authorization credentials
    ClientSecretBasic,

    /// `client_secret_post`: `client_id` and `client_secret` sent in the
    /// request body
    ClientSecretPost,

    /// `client_secret_jwt`: a `client_assertion` sent in the request body and
    /// signed using the `client_secret`
    ClientSecretJwt,

    /// `private_key_jwt`: a `client_assertion` sent in the request body and
    /// signed by an asymmetric key
    PrivateKeyJwt,

    /// `sign_in_with_apple`: a special method for Signin with Apple
    SignInWithApple,
}

/// How to handle a claim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
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
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, ImportAction::Ignore)
    }
}

/// Should the email address be marked as verified
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SetEmailVerification {
    /// Mark the email address as verified
    Always,

    /// Don't mark the email address as verified
    Never,

    /// Mark the email address as verified if the upstream provider says it is
    /// through the `email_verified` claim
    #[default]
    Import,
}

impl SetEmailVerification {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, SetEmailVerification::Import)
    }
}

/// What should be done for the subject attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct SubjectImportPreference {
    /// The Jinja2 template to use for the subject attribute
    ///
    /// If not provided, the default template is `{{ user.sub }}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl SubjectImportPreference {
    const fn is_default(&self) -> bool {
        self.template.is_none()
    }
}

/// What should be done for the localpart attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct LocalpartImportPreference {
    /// How to handle the attribute
    #[serde(default, skip_serializing_if = "ImportAction::is_default")]
    pub action: ImportAction,

    /// The Jinja2 template to use for the localpart attribute
    ///
    /// If not provided, the default template is `{{ user.preferred_username }}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl LocalpartImportPreference {
    const fn is_default(&self) -> bool {
        self.action.is_default() && self.template.is_none()
    }
}

/// What should be done for the displayname attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct DisplaynameImportPreference {
    /// How to handle the attribute
    #[serde(default, skip_serializing_if = "ImportAction::is_default")]
    pub action: ImportAction,

    /// The Jinja2 template to use for the displayname attribute
    ///
    /// If not provided, the default template is `{{ user.name }}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl DisplaynameImportPreference {
    const fn is_default(&self) -> bool {
        self.action.is_default() && self.template.is_none()
    }
}

/// What should be done with the email attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct EmailImportPreference {
    /// How to handle the claim
    #[serde(default, skip_serializing_if = "ImportAction::is_default")]
    pub action: ImportAction,

    /// The Jinja2 template to use for the email address attribute
    ///
    /// If not provided, the default template is `{{ user.email }}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,

    /// Should the email address be marked as verified
    #[serde(default, skip_serializing_if = "SetEmailVerification::is_default")]
    pub set_email_verification: SetEmailVerification,
}

impl EmailImportPreference {
    const fn is_default(&self) -> bool {
        self.action.is_default()
            && self.template.is_none()
            && self.set_email_verification.is_default()
    }
}

/// What should be done for the account name attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct AccountNameImportPreference {
    /// The Jinja2 template to use for the account name. This name is only used
    /// for display purposes.
    ///
    /// If not provided, it will be ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl AccountNameImportPreference {
    const fn is_default(&self) -> bool {
        self.template.is_none()
    }
}

/// How claims should be imported
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct ClaimsImports {
    /// How to determine the subject of the user
    #[serde(default, skip_serializing_if = "SubjectImportPreference::is_default")]
    pub subject: SubjectImportPreference,

    /// Import the localpart of the MXID
    #[serde(default, skip_serializing_if = "LocalpartImportPreference::is_default")]
    pub localpart: LocalpartImportPreference,

    /// Import the displayname of the user.
    #[serde(
        default,
        skip_serializing_if = "DisplaynameImportPreference::is_default"
    )]
    pub displayname: DisplaynameImportPreference,

    /// Import the email address of the user based on the `email` and
    /// `email_verified` claims
    #[serde(default, skip_serializing_if = "EmailImportPreference::is_default")]
    pub email: EmailImportPreference,

    /// Set a human-readable name for the upstream account for display purposes
    #[serde(
        default,
        skip_serializing_if = "AccountNameImportPreference::is_default"
    )]
    pub account_name: AccountNameImportPreference,
}

impl ClaimsImports {
    const fn is_default(&self) -> bool {
        self.subject.is_default()
            && self.localpart.is_default()
            && self.displayname.is_default()
            && self.email.is_default()
    }
}

/// How to discover the provider's configuration
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    /// Use OIDC discovery with strict metadata verification
    #[default]
    Oidc,

    /// Use OIDC discovery with relaxed metadata verification
    Insecure,

    /// Use a static configuration
    Disabled,
}

impl DiscoveryMode {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, DiscoveryMode::Oidc)
    }
}

/// Whether to use proof key for code exchange (PKCE) when requesting and
/// exchanging the token.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum PkceMethod {
    /// Use PKCE if the provider supports it
    ///
    /// Defaults to no PKCE if provider discovery is disabled
    #[default]
    Auto,

    /// Always use PKCE with the S256 challenge method
    Always,

    /// Never use PKCE
    Never,
}

impl PkceMethod {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, PkceMethod::Auto)
    }
}

fn default_true() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_true(value: &bool) -> bool {
    *value
}

#[allow(clippy::ref_option)]
fn is_signed_response_alg_default(signed_response_alg: &JsonWebSignatureAlg) -> bool {
    *signed_response_alg == signed_response_alg_default()
}

#[allow(clippy::unnecessary_wraps)]
fn signed_response_alg_default() -> JsonWebSignatureAlg {
    JsonWebSignatureAlg::Rs256
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignInWithApple {
    /// The private key used to sign the `id_token`
    pub private_key: String,

    /// The Team ID of the Apple Developer Portal
    pub team_id: String,

    /// The key ID of the Apple Developer Portal
    pub key_id: String,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Provider {
    /// Whether this provider is enabled.
    ///
    /// Defaults to `true`
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub enabled: bool,

    /// An internal unique identifier for this provider
    #[schemars(
        with = "String",
        regex(pattern = r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$"),
        description = "A ULID as per https://github.com/ulid/spec"
    )]
    pub id: Ulid,

    /// The OIDC issuer URL
    pub issuer: String,

    /// A human-readable name for the provider, that will be shown to users
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_name: Option<String>,

    /// A brand identifier used to customise the UI, e.g. `apple`, `google`,
    /// `github`, etc.
    ///
    /// Values supported by the default template are:
    ///
    ///  - `apple`
    ///  - `google`
    ///  - `facebook`
    ///  - `github`
    ///  - `gitlab`
    ///  - `twitter`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand_name: Option<String>,

    /// The client ID to use when authenticating with the provider
    pub client_id: String,

    /// The client secret to use when authenticating with the provider
    ///
    /// Used by the `client_secret_basic`, `client_secret_post`, and
    /// `client_secret_jwt` methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// The method to authenticate the client with the provider
    pub token_endpoint_auth_method: TokenAuthMethod,

    /// Additional parameters for the `sign_in_with_apple` method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_with_apple: Option<SignInWithApple>,

    /// The JWS algorithm to use when authenticating the client with the
    /// provider
    ///
    /// Used by the `client_secret_jwt` and `private_key_jwt` methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,

    /// Expected signature for the JWT payload returned by the token
    /// authentication endpoint.
    ///
    /// Defaults to `RS256`.
    #[serde(
        default = "signed_response_alg_default",
        skip_serializing_if = "is_signed_response_alg_default"
    )]
    pub id_token_signed_response_alg: JsonWebSignatureAlg,

    /// The scopes to request from the provider
    pub scope: String,

    /// How to discover the provider's configuration
    ///
    /// Defaults to `oidc`, which uses OIDC discovery with strict metadata
    /// verification
    #[serde(default, skip_serializing_if = "DiscoveryMode::is_default")]
    pub discovery_mode: DiscoveryMode,

    /// Whether to use proof key for code exchange (PKCE) when requesting and
    /// exchanging the token.
    ///
    /// Defaults to `auto`, which uses PKCE if the provider supports it.
    #[serde(default, skip_serializing_if = "PkceMethod::is_default")]
    pub pkce_method: PkceMethod,

    /// Whether to fetch the user profile from the userinfo endpoint,
    /// or to rely on the data returned in the `id_token` from the
    /// `token_endpoint`.
    ///
    /// Defaults to `false`.
    #[serde(default)]
    pub fetch_userinfo: bool,

    /// Expected signature for the JWT payload returned by the userinfo
    /// endpoint.
    ///
    /// If not specified, the response is expected to be an unsigned JSON payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// The URL to use for the provider's authorization endpoint
    ///
    /// Defaults to the `authorization_endpoint` provided through discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<Url>,

    /// The URL to use for the provider's userinfo endpoint
    ///
    /// Defaults to the `userinfo_endpoint` provided through discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<Url>,

    /// The URL to use for the provider's token endpoint
    ///
    /// Defaults to the `token_endpoint` provided through discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<Url>,

    /// The URL to use for getting the provider's public keys
    ///
    /// Defaults to the `jwks_uri` provided through discovery
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<Url>,

    /// The response mode we ask the provider to use for the callback
    #[serde(default, skip_serializing_if = "ResponseMode::is_default")]
    pub response_mode: ResponseMode,

    /// How claims should be imported from the `id_token` provided by the
    /// provider
    #[serde(default, skip_serializing_if = "ClaimsImports::is_default")]
    pub claims_imports: ClaimsImports,

    /// Additional parameters to include in the authorization request
    ///
    /// Orders of the keys are not preserved.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_authorization_parameters: BTreeMap<String, String>,
}
