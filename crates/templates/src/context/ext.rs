// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use mas_data_model::SiteConfig;

use super::{SiteBranding, SiteFeatures};

mod private {
    pub trait Sealed {}
    impl Sealed for mas_data_model::SiteConfig {}
}

/// Extension trait for [`SiteConfig`] to construct [`SiteBranding`] and
/// [`SiteFeatures`] from it.
pub trait SiteConfigExt: private::Sealed {
    /// Construct a [`SiteBranding`] from the [`SiteConfig`].
    fn templates_branding(&self) -> SiteBranding;

    /// Construct a [`SiteFeatures`] from the [`SiteConfig`].
    fn templates_features(&self) -> SiteFeatures;
}

impl SiteConfigExt for SiteConfig {
    fn templates_branding(&self) -> SiteBranding {
        let mut branding = SiteBranding::new(self.server_name.clone());

        if let Some(policy_uri) = &self.policy_uri {
            branding = branding.with_policy_uri(policy_uri.as_str());
        }

        if let Some(tos_uri) = &self.tos_uri {
            branding = branding.with_tos_uri(tos_uri.as_str());
        }

        if let Some(imprint) = &self.imprint {
            branding = branding.with_imprint(imprint.as_str());
        }

        branding
    }

    fn templates_features(&self) -> SiteFeatures {
        SiteFeatures {
            password_registration: self.password_registration_enabled,
            password_registration_email_required: self.password_registration_email_required,
            password_login: self.password_login_enabled,
            account_recovery: self.account_recovery_allowed,
            login_with_email_allowed: self.login_with_email_allowed,
            passkeys_enabled: self.passkeys_enabled,
        }
    }
}
