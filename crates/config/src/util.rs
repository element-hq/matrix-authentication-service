// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use figment::Figment;
use serde::de::DeserializeOwned;

/// Trait implemented by all configuration section to help loading specific part
/// of the config and generate the sample config.
pub trait ConfigurationSection: Sized + DeserializeOwned {
    /// Specify where this section should live relative to the root.
    const PATH: Option<&'static str> = None;

    /// Validate the configuration section
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid
    fn validate(
        &self,
        _figment: &Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(())
    }

    /// Extract configuration from a Figment instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration could not be loaded
    fn extract(
        figment: &Figment,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let this: Self = if let Some(path) = Self::PATH {
            figment.extract_inner(path)?
        } else {
            figment.extract()?
        };

        this.validate(figment)?;
        Ok(this)
    }
}

/// Extension trait for [`ConfigurationSection`] to allow extracting the
/// configuration section from a [`Figment`] or return the default value if the
/// section is not present.
pub trait ConfigurationSectionExt: ConfigurationSection + Default {
    /// Extract the configuration section from the given [`Figment`], or return
    /// the default value if the section is not present.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration section is invalid.
    fn extract_or_default(
        figment: &Figment,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let this: Self = if let Some(path) = Self::PATH {
            // If the configuration section is not present, we return the default value
            if !figment.contains(path) {
                return Ok(Self::default());
            }

            figment.extract_inner(path)?
        } else {
            figment.extract()?
        };

        this.validate(figment)?;
        Ok(this)
    }
}

impl<T: ConfigurationSection + Default> ConfigurationSectionExt for T {}
