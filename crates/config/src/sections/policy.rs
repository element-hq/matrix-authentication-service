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

/// Application secrets
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyConfig {
    /// Path to the WASM module
    #[serde(
        default = "default_policy_path",
        skip_serializing_if = "is_default_policy_path"
    )]
    #[schemars(with = "String")]
    pub wasm_module: Utf8PathBuf,

    /// Entrypoint to use when evaluating client registrations
    #[serde(
        default = "default_client_registration_entrypoint",
        skip_serializing_if = "is_default_client_registration_entrypoint"
    )]
    pub client_registration_entrypoint: String,

    /// Entrypoint to use when evaluating user registrations
    #[serde(
        default = "default_register_entrypoint",
        skip_serializing_if = "is_default_register_entrypoint"
    )]
    pub register_entrypoint: String,

    /// Entrypoint to use when evaluating authorization grants
    #[serde(
        default = "default_authorization_grant_entrypoint",
        skip_serializing_if = "is_default_authorization_grant_entrypoint"
    )]
    pub authorization_grant_entrypoint: String,

    /// Entrypoint to use when evaluating compatibility logins
    #[serde(
        default = "default_compat_login_entrypoint",
        skip_serializing_if = "is_default_compat_login_entrypoint"
    )]
    pub compat_login_entrypoint: String,

    /// Entrypoint to use when changing password
    #[serde(
        default = "default_password_entrypoint",
        skip_serializing_if = "is_default_password_entrypoint"
    )]
    pub password_entrypoint: String,

    /// Entrypoint to use when adding an email address
    #[serde(
        default = "default_email_entrypoint",
        skip_serializing_if = "is_default_email_entrypoint"
    )]
    pub email_entrypoint: String,

    /// Arbitrary data to pass to the policy
    #[serde(default = "default_data", skip_serializing_if = "is_default_data")]
    pub data: serde_json::Value,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            wasm_module: default_policy_path(),
            client_registration_entrypoint: default_client_registration_entrypoint(),
            register_entrypoint: default_register_entrypoint(),
            authorization_grant_entrypoint: default_authorization_grant_entrypoint(),
            compat_login_entrypoint: default_compat_login_entrypoint(),
            password_entrypoint: default_password_entrypoint(),
            email_entrypoint: default_email_entrypoint(),
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
