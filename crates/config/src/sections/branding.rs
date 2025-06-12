// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ConfigurationSection;

/// Configuration section for tweaking the branding of the service
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize, Default)]
pub struct BrandingConfig {
    /// A human-readable name. Defaults to the server's address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    /// Link to a privacy policy, displayed in the footer of web pages and
    /// emails. It is also advertised to clients through the `op_policy_uri`
    /// OIDC provider metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<Url>,

    /// Link to a terms of service document, displayed in the footer of web
    /// pages and emails. It is also advertised to clients through the
    /// `op_tos_uri` OIDC provider metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<Url>,

    /// Legal imprint, displayed in the footer in the footer of web pages and
    /// emails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imprint: Option<String>,

    /// Logo displayed in some web pages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<Url>,
}

impl BrandingConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        self.service_name.is_none()
            && self.policy_uri.is_none()
            && self.tos_uri.is_none()
            && self.imprint.is_none()
            && self.logo_uri.is_none()
    }
}

impl ConfigurationSection for BrandingConfig {
    const PATH: Option<&'static str> = Some("branding");
}
