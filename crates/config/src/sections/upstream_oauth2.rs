// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use mas_iana::jose::JsonWebSignatureAlg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};
use serde_with::{serde_as, skip_serializing_none};
use ulid::Ulid;
use url::Url;

use crate::{ClientSecret, ClientSecretRaw, ConfigurationSection};

/// Settings related to upstream OAuth 2.0/OIDC providers.
/// Additions and modifications within this section are synced with the database
/// on server startup. Removed entries are only removed with the [`config sync
/// --prune`](./cli/config.md#config-sync---prune---dry-run) command.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct UpstreamOAuth2Config {
    /// A list of upstream OAuth 2.0/OIDC providers to use to authenticate
    /// users.
    ///
    /// Sample configurations for popular providers can be found in the
    /// [upstream provider setup](../setup/sso.md#sample-configurations) guide.
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

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
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
                error
            };

            if !matches!(provider.discovery_mode, DiscoveryMode::Disabled)
                && provider.issuer.is_none()
            {
                return Err(annotate(figment::Error::custom(
                    "The `issuer` field is required when discovery is enabled",
                ))
                .into());
            }

            match provider.token_endpoint_auth_method {
                TokenAuthMethod::None
                | TokenAuthMethod::PrivateKeyJwt
                | TokenAuthMethod::SignInWithApple => {
                    if provider.client_secret.is_some() {
                        return Err(annotate(figment::Error::custom(
                            "Unexpected field `client_secret` for the selected authentication method",
                        )).into());
                    }
                }
                TokenAuthMethod::ClientSecretBasic
                | TokenAuthMethod::ClientSecretPost
                | TokenAuthMethod::ClientSecretJwt => {
                    if provider.client_secret.is_none() {
                        return Err(annotate(figment::Error::missing_field("client_secret")).into());
                    }
                }
            }

            match provider.token_endpoint_auth_method {
                TokenAuthMethod::None
                | TokenAuthMethod::ClientSecretBasic
                | TokenAuthMethod::ClientSecretPost
                | TokenAuthMethod::SignInWithApple => {
                    if provider.token_endpoint_auth_signing_alg.is_some() {
                        return Err(annotate(figment::Error::custom(
                            "Unexpected field `token_endpoint_auth_signing_alg` for the selected authentication method",
                        )).into());
                    }
                }
                TokenAuthMethod::ClientSecretJwt | TokenAuthMethod::PrivateKeyJwt => {
                    if provider.token_endpoint_auth_signing_alg.is_none() {
                        return Err(annotate(figment::Error::missing_field(
                            "token_endpoint_auth_signing_alg",
                        ))
                        .into());
                    }
                }
            }

            match provider.token_endpoint_auth_method {
                TokenAuthMethod::SignInWithApple => {
                    if provider.sign_in_with_apple.is_none() {
                        return Err(
                            annotate(figment::Error::missing_field("sign_in_with_apple")).into(),
                        );
                    }
                }

                _ => {
                    if provider.sign_in_with_apple.is_some() {
                        return Err(annotate(figment::Error::custom(
                            "Unexpected field `sign_in_with_apple` for the selected authentication method",
                        )).into());
                    }
                }
            }

            if provider.claims_imports.skip_confirmation {
                if provider.claims_imports.localpart.action != ImportAction::Require {
                    return Err(annotate(figment::Error::custom(
                        "The field `action` must be `require` when `skip_confirmation` is set to `true`",
                    )).with_path("claims_imports.localpart").into());
                }

                if provider.claims_imports.email.action == ImportAction::Suggest {
                    return Err(annotate(figment::Error::custom(
                        "The field `action` must not be `suggest` when `skip_confirmation` is set to `true`",
                    )).with_path("claims_imports.email").into());
                }

                if provider.claims_imports.displayname.action == ImportAction::Suggest {
                    return Err(annotate(figment::Error::custom(
                        "The field `action` must not be `suggest` when `skip_confirmation` is set to `true`",
                    )).with_path("claims_imports.displayname").into());
                }
            }

            if matches!(
                provider.claims_imports.localpart.on_conflict,
                OnConflict::Add | OnConflict::Replace | OnConflict::Set
            ) && !matches!(
                provider.claims_imports.localpart.action,
                ImportAction::Force | ImportAction::Require
            ) {
                return Err(annotate(figment::Error::custom(
                    "The field `action` must be either `force` or `require` when `on_conflict` is set to `add`, `replace` or `set`",
                )).with_path("claims_imports.localpart").into());
            }
        }

        Ok(())
    }
}

/// The response mode we ask the provider to use for the callback
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// The provider will send the response as a query string in the URL search
    /// parameters. This is the default.
    Query,

    /// The provider will send the response as a POST request with the response
    /// parameters in the request body
    FormPost,
}

/// Authentication methods used against the OAuth 2.0 provider
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuthMethod {
    /// No authentication
    None,

    /// `client_id` and `client_secret` used as basic authorization credentials
    ClientSecretBasic,

    /// `client_id` and `client_secret` sent in the request body
    ClientSecretPost,

    /// a `client_assertion` sent in the request body and signed using the
    /// `client_secret`
    ClientSecretJwt,

    /// a `client_assertion` sent in the request body and signed by an
    /// asymmetric key, using the keys defined in the `secrets.keys` section
    PrivateKeyJwt,

    /// a special authentication method for Sign-in with Apple
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
    #[expect(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, ImportAction::Ignore)
    }
}

/// How to handle an existing localpart claim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OnConflict {
    /// Fails the upstream OAuth 2.0 login.
    #[default]
    Fail,

    /// Adds the upstream account link to the existing user, regardless of
    /// whether there is an existing link or not.
    Add,

    /// Replace any existing upstream OAuth 2.0 identity link for this provider
    /// on the matching user.
    Replace,

    /// Adds the upstream account link *only* if there is no existing link for
    /// this provider on the matching user.
    Set,
}

impl OnConflict {
    #[expect(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, OnConflict::Fail)
    }
}

/// What should be done for the subject attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct SubjectImportPreference {
    /// The Jinja2 template to use for the subject attribute
    ///
    /// If not provided, the default template is `{{ user.sub }}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"{{ user.sub }}", extend("x-doc" = {"commented": true}))]
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
    #[schemars(example = &ImportAction::Force, extend("x-doc" = {"commented": true}))]
    pub action: ImportAction,

    /// The Jinja2 template to use for the localpart attribute
    ///
    /// If not provided, the default template is `{{ user.preferred_username }}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"{{ user.preferred_username }}", extend("x-doc" = {"commented": true}))]
    pub template: Option<String>,

    /// How to handle when localpart already exists.
    #[serde(default, skip_serializing_if = "OnConflict::is_default")]
    #[schemars(example = &OnConflict::Fail, extend("x-doc" = {"commented": true}))]
    pub on_conflict: OnConflict,
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
    #[schemars(example = &ImportAction::Suggest, extend("x-doc" = {"commented": true}))]
    pub action: ImportAction,

    /// The Jinja2 template to use for the displayname attribute
    ///
    /// If not provided, the default template is `{{ user.name }}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"{{ user.name }}", extend("x-doc" = {"commented": true}))]
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
    #[schemars(example = &ImportAction::Suggest, extend("x-doc" = {"commented": true}))]
    pub action: ImportAction,

    /// The Jinja2 template to use for the email address attribute
    ///
    /// If not provided, the default template is `{{ user.email }}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"{{ user.email }}", extend("x-doc" = {"commented": true}))]
    pub template: Option<String>,
}

impl EmailImportPreference {
    const fn is_default(&self) -> bool {
        self.action.is_default() && self.template.is_none()
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
    #[schemars(example = &"@{{ user.preferred_username }}", extend("x-doc" = {"commented": true}))]
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
    /// The subject is an internal identifier used to link the user's provider
    /// identity to local accounts.
    /// By default it uses the `sub` claim as per the OIDC spec, which should
    /// fit most use cases.
    #[serde(default, skip_serializing_if = "SubjectImportPreference::is_default")]
    pub subject: SubjectImportPreference,

    /// By default, new users will see a screen confirming the attributes they
    /// are about to have on their account.
    ///
    /// Setting this to `true` allows skipping this screen, but requires the
    /// `localpart.action` to be set to `require` and the other attributes
    /// actions to be set to `ignore`, `force` or `require`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[schemars(example = &false, extend("x-doc" = {"commented": true}))]
    pub skip_confirmation: bool,

    /// The localpart is the local part of the user's Matrix ID.
    /// For example, on the `example.com` server, if the localpart is `alice`,
    /// the user's Matrix ID will be `@alice:example.com`.
    #[serde(default, skip_serializing_if = "LocalpartImportPreference::is_default")]
    pub localpart: LocalpartImportPreference,

    /// The display name is the user's display name.
    #[serde(
        default,
        skip_serializing_if = "DisplaynameImportPreference::is_default"
    )]
    pub displayname: DisplaynameImportPreference,

    /// An email address to import.
    #[serde(default, skip_serializing_if = "EmailImportPreference::is_default")]
    pub email: EmailImportPreference,

    /// An account name, for display purposes only.
    ///
    /// This helps the end user identify what account they are using
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
            && !self.skip_confirmation
            && self.displayname.is_default()
            && self.email.is_default()
            && self.account_name.is_default()
    }
}

/// How to discover the provider's configuration
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    /// discover the provider through OIDC discovery, with strict metadata
    /// validation (default)
    #[default]
    Oidc,

    /// discover through OIDC discovery, but skip metadata validation
    Insecure,

    /// don't discover the provider and use the endpoints below
    Disabled,
}

impl DiscoveryMode {
    #[expect(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, DiscoveryMode::Oidc)
    }
}

/// Whether to use proof key for code exchange (PKCE) when requesting and
/// exchanging the token.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum PkceMethod {
    /// use PKCE if the provider supports it (default).
    /// Determined through discovery, and disabled if discovery is disabled
    #[default]
    Auto,

    /// always use PKCE (with the S256 method)
    Always,

    /// never use PKCE
    Never,
}

impl PkceMethod {
    #[expect(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, PkceMethod::Auto)
    }
}

fn default_true() -> bool {
    true
}

#[expect(clippy::trivially_copy_pass_by_ref)]
fn is_default_true(value: &bool) -> bool {
    *value
}

fn is_signed_response_alg_default(signed_response_alg: &JsonWebSignatureAlg) -> bool {
    *signed_response_alg == signed_response_alg_default()
}

fn signed_response_alg_default() -> JsonWebSignatureAlg {
    JsonWebSignatureAlg::Rs256
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignInWithApple {
    /// The private key file used to sign the `id_token`
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>", example = &"/path/to/private.key")]
    pub private_key_file: Option<Utf8PathBuf>,

    /// The private key used to sign the `id_token`
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")]
    pub private_key: Option<String>,

    /// The Team ID of the Apple Developer Portal
    #[schemars(example = &"<team-id>")]
    pub team_id: String,

    /// The key ID of the Apple Developer Portal
    #[schemars(example = &"<key-id>")]
    pub key_id: String,
}

fn default_scope() -> String {
    "openid".to_owned()
}

fn is_default_scope(scope: &str) -> bool {
    scope == default_scope()
}

/// What to do when receiving an OIDC Backchannel logout request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnBackchannelLogout {
    /// do nothing, other than validating and logging the request
    #[default]
    DoNothing,

    /// Only log out the MAS 'browser session' started by this OIDC session
    LogoutBrowserOnly,

    /// Log out all sessions started by this OIDC session, including MAS
    /// 'browser sessions' and client sessions
    LogoutAll,
}

impl OnBackchannelLogout {
    #[expect(clippy::trivially_copy_pass_by_ref)]
    const fn is_default(&self) -> bool {
        matches!(self, OnBackchannelLogout::DoNothing)
    }
}

/// Configuration for one upstream OAuth 2 provider.
#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[expect(clippy::struct_excessive_bools)]
pub struct Provider {
    /// A unique identifier for the provider.
    ///
    /// Must be a valid ULID
    #[schemars(
        with = "String",
        regex(pattern = r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$"),
        description = "A unique identifier for the provider.\n\nMust be a valid ULID",
        example = &"01HFVBY12TMNTYTBV8W921M5FA"
    )]
    pub id: Ulid,

    /// Whether this provider is enabled. Defaults to `true`.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    #[schemars(example = &true, extend("x-doc" = {"commented": true}))]
    pub enabled: bool,

    /// The ID of the provider that was used by Synapse.
    /// Only required when performing a Synapse-to-MAS migration.
    /// For Synapse's `oidc_providers`, this is `oidc-<idp_id>`; for the legacy
    /// `oidc_config`, this is `oidc`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"oidc-github", extend("x-doc" = {"commented": true}))]
    pub synapse_idp_id: Option<String>,

    /// The issuer URL, which will be used to discover the provider's
    /// configuration. If discovery is enabled, this *must* exactly match the
    /// `issuer` field advertised in
    /// `<issuer>/.well-known/openid-configuration`. It must be set if OIDC
    /// discovery is enabled (which is the default).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"https://example.com/", extend("x-doc" = {"commented": true}))]
    pub issuer: Option<String>,

    /// A human-readable name for the provider, which will be displayed on the
    /// login page
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"Example", extend("x-doc" = {"commented": true}))]
    pub human_name: Option<String>,

    /// A brand identifier for the provider, which will be used to display a
    /// logo on the login page. Values supported by the default template
    /// are:
    ///  - `apple`
    ///  - `google`
    ///  - `facebook`
    ///  - `github`
    ///  - `gitlab`
    ///  - `twitter`
    ///  - `discord`
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"google", extend("x-doc" = {"commented": true}))]
    pub brand_name: Option<String>,

    /// The client ID to use to authenticate to the provider
    #[schemars(example = &"mas-fb3f0c09c4c23de4")]
    pub client_id: String,

    /// The client secret to use when authenticating with the provider
    ///
    /// Used by the `client_secret_basic`, `client_secret_post`, and
    /// `client_secret_jwt` methods
    #[schemars(with = "ClientSecretRaw")]
    #[serde_as(as = "serde_with::TryFromInto<ClientSecretRaw>")]
    #[serde(flatten)]
    pub client_secret: Option<ClientSecret>,

    /// The method to authenticate the client with the provider
    #[schemars(example = &TokenAuthMethod::ClientSecretPost)]
    pub token_endpoint_auth_method: TokenAuthMethod,

    /// Additional parameters for the `sign_in_with_apple` authentication method
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-doc" = {"commented": true}))]
    pub sign_in_with_apple: Option<SignInWithApple>,

    /// The JWS algorithm to use when authenticating the client with the
    /// provider
    ///
    /// Used by the `client_secret_jwt` and `private_key_jwt` methods
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &JsonWebSignatureAlg::Rs256, extend("x-doc" = {"commented": true}))]
    pub token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,

    /// Expected signature for the JWT payload returned by the token
    /// authentication endpoint.
    ///
    /// Defaults to `RS256`.
    #[serde(
        default = "signed_response_alg_default",
        skip_serializing_if = "is_signed_response_alg_default"
    )]
    #[schemars(example = &JsonWebSignatureAlg::Rs256, extend("x-doc" = {"commented": true}))]
    pub id_token_signed_response_alg: JsonWebSignatureAlg,

    /// The scopes to request from the provider.
    ///
    /// In most cases, it should always include the `openid` scope
    #[serde(default = "default_scope", skip_serializing_if = "is_default_scope")]
    #[schemars(example = &"openid email profile")]
    pub scope: String,

    /// How the provider configuration and endpoints should be discovered
    #[serde(default, skip_serializing_if = "DiscoveryMode::is_default")]
    #[schemars(example = &DiscoveryMode::Oidc, extend("x-doc" = {"commented": true}))]
    pub discovery_mode: DiscoveryMode,

    /// Whether PKCE should be used during the authorization code flow.
    #[serde(default, skip_serializing_if = "PkceMethod::is_default")]
    #[schemars(example = &PkceMethod::Auto, extend("x-doc" = {"commented": true}))]
    pub pkce_method: PkceMethod,

    /// Whether to fetch user claims from the userinfo endpoint.
    ///
    /// This is disabled by default, as most providers will return the necessary
    /// claims in the `id_token`
    #[serde(default)]
    #[schemars(example = &true, extend("x-doc" = {"commented": true}))]
    pub fetch_userinfo: bool,

    /// Expected signature for the JWT payload returned by the userinfo
    /// endpoint.
    ///
    /// If not specified, the response is expected to be an unsigned JSON
    /// payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &JsonWebSignatureAlg::Rs256, extend("x-doc" = {"commented": true}))]
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// The userinfo endpoint.
    ///
    /// This takes precedence over the discovery mechanism
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"https://example.com/oauth2/userinfo", extend("x-doc" = {"commented": true}))]
    pub userinfo_endpoint: Option<Url>,

    /// The provider authorization endpoint.
    ///
    /// This takes precedence over the discovery mechanism
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"https://example.com/oauth2/authorize", extend("x-doc" = {"commented": true}))]
    pub authorization_endpoint: Option<Url>,

    /// The provider token endpoint.
    ///
    /// This takes precedence over the discovery mechanism
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"https://example.com/oauth2/token", extend("x-doc" = {"commented": true}))]
    pub token_endpoint: Option<Url>,

    /// The provider JWKS URI.
    ///
    /// This takes precedence over the discovery mechanism
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"https://example.com/oauth2/keys", extend("x-doc" = {"commented": true}))]
    pub jwks_uri: Option<Url>,

    /// The response mode we ask the provider to use for the callback
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &ResponseMode::Query, extend("x-doc" = {"commented": true}))]
    pub response_mode: Option<ResponseMode>,

    /// Additional parameters to include in the authorization request.
    ///
    /// Values are Jinja2 templates rendered against a `params` map containing
    /// the raw query parameters of the downstream authorization request (empty
    /// when the upstream login was not triggered by a downstream authorization
    /// request, e.g. account linking or direct login). Templates that render to
    /// an empty string are dropped rather than forwarded.
    ///
    /// Plain strings without `{{ … }}` render to themselves, so static values
    /// work as expected.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(example = &serde_json::json!({
        "foo": "bar",
        "login_hint": "{{ params.login_hint }}",
        "acr_values": "{{ params.acr_values }}",
    }), extend("x-doc" = {"commented": true}))]
    pub additional_authorization_parameters: BTreeMap<String, String>,

    /// Whether the `login_hint` should be forwarded to the provider in the
    /// authorization request.
    ///
    /// Deprecated: prefer adding `login_hint: "{{ params.login_hint }}"` to
    /// `additional_authorization_parameters` instead. When this flag is set, a
    /// `login_hint` template entry is injected automatically if one is not
    /// already present.
    #[serde(default)]
    #[schemars(extend("x-doc" = {"commented": true}))]
    pub forward_login_hint: bool,

    /// What to do when receiving an OIDC Backchannel logout request.
    #[serde(default, skip_serializing_if = "OnBackchannelLogout::is_default")]
    #[schemars(example = &OnBackchannelLogout::DoNothing, extend("x-doc" = {"commented": true}))]
    pub on_backchannel_logout: OnBackchannelLogout,

    /// Whether a registration token is required to register through this
    /// provider. Defaults to `false`.
    #[serde(default)]
    #[schemars(extend("x-doc" = {"commented": true}))]
    pub registration_token_required: bool,

    /// How user attributes should be mapped
    ///
    /// Most of those attributes have two main properties:
    ///   - `action`: what to do with the attribute. Possible values are:
    ///      - `ignore`: ignore the attribute
    ///      - `suggest`: suggest the attribute to the user, but let them opt
    ///        out
    ///      - `force`: always import the attribute, and don't fail if it's
    ///        missing
    ///      - `require`: always import the attribute, and fail if it's missing
    ///   - `template`: a Jinja2 template used to generate the value. In this
    ///     template, the `user` variable is available, which contains the
    ///     user's attributes retrieved from the `id_token` given by the
    ///     upstream provider and/or through the userinfo endpoint.
    ///
    /// Each attribute has a default template which follows the well-known OIDC
    /// claims.
    #[serde(default, skip_serializing_if = "ClaimsImports::is_default")]
    pub claims_imports: ClaimsImports,
}

impl Provider {
    /// Returns the client secret.
    ///
    /// If `client_secret_file` was given, the secret is read from that file.
    ///
    /// # Errors
    ///
    /// Returns an error when the client secret could not be read from file.
    pub async fn client_secret(&self) -> anyhow::Result<Option<String>> {
        Ok(match &self.client_secret {
            Some(client_secret) => Some(client_secret.value().await?),
            None => None,
        })
    }
}

#[cfg(test)]
mod tests {
    // The closures passed to `Jail::expect_with` return `figment::Error`, which is
    // large, and we can't change figment's API.
    #![expect(clippy::result_large_err)]

    use std::str::FromStr;

    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };
    use tokio::{runtime::Handle, task};

    use super::*;

    #[tokio::test]
    async fn load_config() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    r#"
                      upstream_oauth2:
                        providers:
                          - id: 01GFWR28C4KNE04WG3HKXB7C9R
                            client_id: upstream-oauth2
                            token_endpoint_auth_method: none

                          - id: 01GFWR32NCQ12B8Z0J8CPXRRB6
                            client_id: upstream-oauth2
                            client_secret_file: secret
                            token_endpoint_auth_method: client_secret_basic

                          - id: 01GFWR3WHR93Y5HK389H28VHZ9
                            client_id: upstream-oauth2
                            client_secret: c1!3n753c237
                            token_endpoint_auth_method: client_secret_post

                          - id: 01GFWR43R2ZZ8HX9CVBNW9TJWG
                            client_id: upstream-oauth2
                            client_secret_file: secret
                            token_endpoint_auth_method: client_secret_jwt

                          - id: 01GFWR4BNFDCC4QDG6AMSP1VRR
                            client_id: upstream-oauth2
                            token_endpoint_auth_method: private_key_jwt
                            jwks:
                              keys:
                              - kid: "03e84aed4ef4431014e8617567864c4efaaaede9"
                                kty: "RSA"
                                alg: "RS256"
                                use: "sig"
                                e: "AQAB"
                                n: "ma2uRyBeSEOatGuDpCiV9oIxlDWix_KypDYuhQfEzqi_BiF4fV266OWfyjcABbam59aJMNvOnKW3u_eZM-PhMCBij5MZ-vcBJ4GfxDJeKSn-GP_dJ09rpDcILh8HaWAnPmMoi4DC0nrfE241wPISvZaaZnGHkOrfN_EnA5DligLgVUbrA5rJhQ1aSEQO_gf1raEOW3DZ_ACU3qhtgO0ZBG3a5h7BPiRs2sXqb2UCmBBgwyvYLDebnpE7AotF6_xBIlR-Cykdap3GHVMXhrIpvU195HF30ZoBU4dMd-AeG6HgRt4Cqy1moGoDgMQfbmQ48Hlunv9_Vi2e2CLvYECcBw"

                              - kid: "d01c1abe249269f72ef7ca2613a86c9f05e59567"
                                kty: "RSA"
                                alg: "RS256"
                                use: "sig"
                                e: "AQAB"
                                n: "0hukqytPwrj1RbMYhYoepCi3CN5k7DwYkTe_Cmb7cP9_qv4ok78KdvFXt5AnQxCRwBD7-qTNkkfMWO2RxUMBdQD0ED6tsSb1n5dp0XY8dSWiBDCX8f6Hr-KolOpvMLZKRy01HdAWcM6RoL9ikbjYHUEW1C8IJnw3MzVHkpKFDL354aptdNLaAdTCBvKzU9WpXo10g-5ctzSlWWjQuecLMQ4G1mNdsR1LHhUENEnOvgT8cDkX0fJzLbEbyBYkdMgKggyVPEB1bg6evG4fTKawgnf0IDSPxIU-wdS9wdSP9ZCJJPLi5CEp-6t6rE_sb2dGcnzjCGlembC57VwpkUvyMw"
                    "#,
                )?;
                jail.create_file("secret", r"c1!3n753c237")?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<UpstreamOAuth2Config>("upstream_oauth2")?;

                assert_eq!(config.providers.len(), 5);

                assert_eq!(
                    config.providers[1].id,
                    Ulid::from_str("01GFWR32NCQ12B8Z0J8CPXRRB6").unwrap()
                );

                assert!(config.providers[0].client_secret.is_none());
                assert!(matches!(config.providers[1].client_secret, Some(ClientSecret::File(ref p)) if p == "secret"));
                assert!(matches!(config.providers[2].client_secret, Some(ClientSecret::Value(ref v)) if v == "c1!3n753c237"));
                assert!(matches!(config.providers[3].client_secret, Some(ClientSecret::File(ref p)) if p == "secret"));
                assert!(config.providers[4].client_secret.is_none());

                Handle::current().block_on(async move {
                    assert_eq!(config.providers[1].client_secret().await.unwrap().unwrap(), "c1!3n753c237");
                    assert_eq!(config.providers[2].client_secret().await.unwrap().unwrap(), "c1!3n753c237");
                    assert_eq!(config.providers[3].client_secret().await.unwrap().unwrap(), "c1!3n753c237");
                });

                Ok(())
            });
        }).await.unwrap();
    }
}
