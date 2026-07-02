// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn default_policy_path() -> Utf8PathBuf {
    "./policies/policy.wasm".into()
}

#[cfg(feature = "docker")]
fn default_policy_path() -> Utf8PathBuf {
    "/usr/local/share/mas-cli/policy.wasm".into()
}

#[cfg(feature = "dist")]
fn default_policy_path() -> Utf8PathBuf {
    "./share/policy.wasm".into()
}

fn is_default_policy_path(value: &Utf8PathBuf) -> bool {
    *value == default_policy_path()
}

fn default_client_registration_entrypoint() -> String {
    "client_registration/violation".to_owned()
}

fn is_default_client_registration_entrypoint(value: &String) -> bool {
    *value == default_client_registration_entrypoint()
}

fn default_register_entrypoint() -> String {
    "register/violation".to_owned()
}

fn is_default_register_entrypoint(value: &String) -> bool {
    *value == default_register_entrypoint()
}

fn default_authorization_grant_entrypoint() -> String {
    "authorization_grant/violation".to_owned()
}

fn is_default_authorization_grant_entrypoint(value: &String) -> bool {
    *value == default_authorization_grant_entrypoint()
}

fn default_password_entrypoint() -> String {
    "password/violation".to_owned()
}

fn is_default_password_entrypoint(value: &String) -> bool {
    *value == default_password_entrypoint()
}

fn default_compat_login_entrypoint() -> String {
    "compat_login/violation".to_owned()
}

fn is_default_compat_login_entrypoint(value: &String) -> bool {
    *value == default_compat_login_entrypoint()
}

fn default_email_entrypoint() -> String {
    "email/violation".to_owned()
}

fn is_default_email_entrypoint(value: &String) -> bool {
    *value == default_email_entrypoint()
}

fn default_data() -> serde_json::Value {
    serde_json::json!({})
}

fn is_default_data(value: &serde_json::Value) -> bool {
    *value == default_data()
}

/// Policy settings
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyConfig {
    /// Path to the WASM module
    ///
    /// The default value depends on how MAS was built:
    ///  - Docker distribution: `/usr/local/share/mas-cli/policy.wasm`
    ///  - pre-built binaries: `./share/policy.wasm`
    ///  - locally-built binaries: `./policies/policy.wasm`
    #[serde(
        default = "default_policy_path",
        skip_serializing_if = "is_default_policy_path"
    )]
    #[schemars(with = "String", example = &"./policies/policy.wasm")]
    pub wasm_module: Utf8PathBuf,

    /// Entrypoint to use when evaluating client registrations
    #[serde(
        default = "default_client_registration_entrypoint",
        skip_serializing_if = "is_default_client_registration_entrypoint"
    )]
    #[schemars(example = &"client_registration/violation")]
    pub client_registration_entrypoint: String,

    /// Entrypoint to use when evaluating user registrations
    #[serde(
        default = "default_register_entrypoint",
        skip_serializing_if = "is_default_register_entrypoint"
    )]
    #[schemars(example = &"register/violation")]
    pub register_entrypoint: String,

    /// Entrypoint to use when evaluating authorization grants
    #[serde(
        default = "default_authorization_grant_entrypoint",
        skip_serializing_if = "is_default_authorization_grant_entrypoint"
    )]
    #[schemars(example = &"authorization_grant/violation")]
    pub authorization_grant_entrypoint: String,

    /// Entrypoint to use when changing password
    #[serde(
        default = "default_password_entrypoint",
        skip_serializing_if = "is_default_password_entrypoint"
    )]
    #[schemars(example = &"password/violation")]
    pub password_entrypoint: String,

    /// Entrypoint to use when adding an email address
    #[serde(
        default = "default_email_entrypoint",
        skip_serializing_if = "is_default_email_entrypoint"
    )]
    #[schemars(example = &"email/violation")]
    pub email_entrypoint: String,

    /// Entrypoint to use when evaluating compatibility logins
    #[serde(
        default = "default_compat_login_entrypoint",
        skip_serializing_if = "is_default_compat_login_entrypoint"
    )]
    #[schemars(example = &"compat_login/violation")]
    pub compat_login_entrypoint: String,

    /// Arbitrary data to pass to the policy
    #[serde(default = "default_data", skip_serializing_if = "is_default_data")]
    #[schemars(extend("x-doc" = {"yaml": r#"
# This data is being passed to the policy
data:
  # Users which are allowed to ask for admin access. If possible, use the
  # can_request_admin flag on users instead.
  admin_users:
    - person1
    - person2

  # Client IDs which are allowed to ask for admin access with a
  # client_credentials grant
  admin_clients:
    - 01H8PKNWKKRPCBW4YGH1RWV279
    - 01HWQCPA5KF10FNCETY9402WGF

  # Dynamic Client Registration
  client_registration:
    # don't require URIs to be on the same host. default: false
    allow_host_mismatch: false
    # allow non-SSL and localhost URIs. default: false
    allow_insecure_uris: false
    # don't require clients to provide a client_uri. default: false
    allow_missing_client_uri: false

  # Restrictions on user registration
  registration:
    # If specified, the username (localpart) *must* match one of the allowed
    # usernames. If unspecified, all usernames are allowed.
    allowed_usernames:
      # Exact usernames that are allowed
      literals: ["alice", "bob"]
      # Substrings that match allowed usernames
      substrings: ["user"]
      # Regular expressions that match allowed usernames
      regexes: ["^[a-z]+$"]
      # Prefixes that match allowed usernames
      prefixes: ["user-"]
      # Suffixes that match allowed usernames
      suffixes: ["-corp"]
    # If specified, the username (localpart) *must not* match one of the
    # banned usernames. If unspecified, all usernames are allowed.
    banned_usernames:
      # Exact usernames that are banned
      literals: ["admin", "root"]
      # Substrings that match banned usernames
      substrings: ["admin", "root"]
      # Regular expressions that match banned usernames
      regexes: ["^admin$", "^root$"]
      # Prefixes that match banned usernames
      prefixes: ["admin-", "root-"]
      # Suffixes that match banned usernames
      suffixes: ["-admin", "-root"]

  # Restrict what email addresses can be added to a user
  emails:
    # If specified, the email address *must* match one of the allowed addresses.
    # If unspecified, all email addresses are allowed.
    allowed_addresses:
      # Exact emails that are allowed
      literals: ["alice@example.com", "bob@example.com"]
      # Regular expressions that match allowed emails
      regexes: ["@example\\.com$"]
      # Suffixes that match allowed emails
      suffixes: ["@example.com"]

    # If specified, the email address *must not* match one of the banned addresses.
    # If unspecified, all email addresses are allowed.
    banned_addresses:
      # Exact emails that are banned
      literals: ["alice@evil.corp", "bob@evil.corp"]
      # Emails that contains those substrings are banned
      substrings: ["evil"]
      # Regular expressions that match banned emails
      regexes: ["@evil\\.corp$"]
      # Suffixes that match banned emails
      suffixes: ["@evil.corp"]
      # Prefixes that match banned emails
      prefixes: ["alice@"]

  requester:
    # List of IP addresses and CIDRs that are not allowed to register
    banned_ips:
      - 192.168.0.1
      - 192.168.1.0/24
      - fe80::/64

    # User agent patterns that are not allowed to register
    banned_user_agents:
      literals: ["Pretend this is Real;"]
      substrings: ["Chrome"]
      regexes: ["Chrome 1.*;"]
      prefixes: ["Mozilla/"]
      suffixes: ["Safari/605.1.15"]
"#}))]
    pub data: serde_json::Value,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            wasm_module: default_policy_path(),
            client_registration_entrypoint: default_client_registration_entrypoint(),
            register_entrypoint: default_register_entrypoint(),
            authorization_grant_entrypoint: default_authorization_grant_entrypoint(),
            password_entrypoint: default_password_entrypoint(),
            email_entrypoint: default_email_entrypoint(),
            compat_login_entrypoint: default_compat_login_entrypoint(),
            data: default_data(),
        }
    }
}

impl PolicyConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        is_default_policy_path(&self.wasm_module)
            && is_default_client_registration_entrypoint(&self.client_registration_entrypoint)
            && is_default_register_entrypoint(&self.register_entrypoint)
            && is_default_authorization_grant_entrypoint(&self.authorization_grant_entrypoint)
            && is_default_password_entrypoint(&self.password_entrypoint)
            && is_default_email_entrypoint(&self.email_entrypoint)
            && is_default_data(&self.data)
    }
}

impl ConfigurationSection for PolicyConfig {
    const PATH: Option<&'static str> = Some("policy");
}
