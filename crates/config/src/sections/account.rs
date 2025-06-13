// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ConfigurationSection;

const fn default_true() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_default_true(value: &bool) -> bool {
    *value == default_true()
}

const fn default_false() -> bool {
    false
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_default_false(value: &bool) -> bool {
    *value == default_false()
}

/// Configuration section to configure features related to account management
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct AccountConfig {
    /// Whether users are allowed to change their email addresses. Defaults to
    /// `true`.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub email_change_allowed: bool,

    /// Whether users are allowed to change their display names. Defaults to
    /// `true`.
    ///
    /// This should be in sync with the policy in the homeserver configuration.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub displayname_change_allowed: bool,

    /// Whether to enable self-service password registration. Defaults to
    /// `false` if password authentication is enabled.
    ///
    /// This has no effect if password login is disabled.
    #[serde(default = "default_false", skip_serializing_if = "is_default_false")]
    pub password_registration_enabled: bool,

    /// Whether users are allowed to change their passwords. Defaults to `true`.
    ///
    /// This has no effect if password login is disabled.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub password_change_allowed: bool,

    /// Whether email-based password recovery is enabled. Defaults to `false`.
    ///
    /// This has no effect if password login is disabled.
    #[serde(default = "default_false", skip_serializing_if = "is_default_false")]
    pub password_recovery_enabled: bool,

    /// Whether users are allowed to delete their own account. Defaults to
    /// `true`.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub account_deactivation_allowed: bool,

    /// Whether users can log in with their email address. Defaults to `false`.
    ///
    /// This has no effect if password login is disabled.
    #[serde(default = "default_false", skip_serializing_if = "is_default_false")]
    pub login_with_email_allowed: bool,

    /// Whether registration tokens are required for password registrations.
    /// Defaults to `false`.
    ///
    /// When enabled, users must provide a valid registration token during
    /// password registration. This has no effect if password registration
    /// is disabled.
    #[serde(default = "default_false", skip_serializing_if = "is_default_false")]
    pub registration_token_required: bool,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            email_change_allowed: default_true(),
            displayname_change_allowed: default_true(),
            password_registration_enabled: default_false(),
            password_change_allowed: default_true(),
            password_recovery_enabled: default_false(),
            account_deactivation_allowed: default_true(),
            login_with_email_allowed: default_false(),
            registration_token_required: default_false(),
        }
    }
}

impl AccountConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        is_default_false(&self.password_registration_enabled)
            && is_default_true(&self.email_change_allowed)
            && is_default_true(&self.displayname_change_allowed)
            && is_default_true(&self.password_change_allowed)
            && is_default_false(&self.password_recovery_enabled)
            && is_default_true(&self.account_deactivation_allowed)
            && is_default_false(&self.login_with_email_allowed)
            && is_default_false(&self.registration_token_required)
    }
}

impl ConfigurationSection for AccountConfig {
    const PATH: Option<&'static str> = Some("account");
}
