// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};

use crate::ConfigurationSection;

/// Which service should be used for CAPTCHA protection
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
pub enum CaptchaServiceKind {
    /// Use Google's reCAPTCHA v2 API
    #[serde(rename = "recaptcha_v2")]
    RecaptchaV2,

    /// Use Cloudflare Turnstile
    #[serde(rename = "cloudflare_turnstile")]
    CloudflareTurnstile,

    /// Use ``HCaptcha``
    #[serde(rename = "hcaptcha")]
    HCaptcha,
}

/// Configuration section to setup CAPTCHA protection on a few operations
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize, Default)]
pub struct CaptchaConfig {
    /// Which service should be used for CAPTCHA protection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<CaptchaServiceKind>,

    /// The site key to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_key: Option<String>,

    /// The secret key to use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
}

impl CaptchaConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        self.service.is_none() && self.site_key.is_none() && self.secret_key.is_none()
    }
}

impl ConfigurationSection for CaptchaConfig {
    const PATH: Option<&'static str> = Some("captcha");

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let metadata = figment.find_metadata(Self::PATH.unwrap());

        let error_on_field = |mut error: figment::error::Error, field: &'static str| {
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned(), field.to_owned()];
            error
        };

        let missing_field = |field: &'static str| {
            error_on_field(figment::error::Error::missing_field(field), field)
        };

        if let Some(CaptchaServiceKind::RecaptchaV2) = self.service {
            if self.site_key.is_none() {
                return Err(missing_field("site_key").into());
            }

            if self.secret_key.is_none() {
                return Err(missing_field("secret_key").into());
            }
        }

        Ok(())
    }
}
