// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::num::NonZeroU32;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};
use url::Url;

use crate::ConfigurationSection;

const fn default_false() -> bool {
    false
}

#[expect(clippy::trivially_copy_pass_by_ref)]
const fn is_default_false(value: &bool) -> bool {
    *value == default_false()
}

/// Seven days: a starting point; shorten it where unused invite links are a
/// concern
fn default_invite_lifetime() -> NonZeroU32 {
    NonZeroU32::new(7 * 24 * 60 * 60).unwrap()
}

#[expect(clippy::trivially_copy_pass_by_ref)]
fn is_default_invite_lifetime(value: &NonZeroU32) -> bool {
    *value == default_invite_lifetime()
}

/// Configuration section for inviting guests to rooms by email
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct GuestInvitesConfig {
    /// Whether the `POST /api/admin/v1/invite-guests` endpoint is enabled.
    /// Defaults to `false`.
    #[serde(default = "default_false", skip_serializing_if = "is_default_false")]
    pub enabled: bool,

    /// The client URL to send invitees to once they are signed in, with
    /// `{room_id}` standing for the room ID, e.g.
    /// `https://app.element.io/#/room/{room_id}`. Required when `enabled` is
    /// set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_room_url: Option<String>,

    /// How long an invite link stays valid, in seconds. Defaults to 7 days.
    #[serde(
        default = "default_invite_lifetime",
        skip_serializing_if = "is_default_invite_lifetime"
    )]
    pub invite_lifetime: NonZeroU32,
}

impl Default for GuestInvitesConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            client_room_url: None,
            invite_lifetime: default_invite_lifetime(),
        }
    }
}

impl GuestInvitesConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        is_default_false(&self.enabled)
            && self.client_room_url.is_none()
            && is_default_invite_lifetime(&self.invite_lifetime)
    }
}

impl ConfigurationSection for GuestInvitesConfig {
    const PATH: Option<&'static str> = Some("guest_invites");

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let metadata = figment.find_metadata(Self::PATH.unwrap());

        let error = |message: &str| -> Box<dyn std::error::Error + Send + Sync + 'static> {
            let mut error = figment::error::Error::custom(message);
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned(), "client_room_url".to_owned()];
            error.into()
        };

        match &self.client_room_url {
            None if self.enabled => return Err(error("missing field `client_room_url`")),
            Some(url) if !url.contains("{room_id}") => {
                return Err(error("must contain `{room_id}`"));
            }
            Some(url)
                if !Url::parse(&url.replace("{room_id}", "room")).is_ok_and(|url| {
                    matches!(url.scheme(), "http" | "https") && url.has_host()
                }) =>
            {
                return Err(error("must be an absolute HTTP or HTTPS URL"));
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // The closures passed to `Jail::expect_with` return `figment::Error`, which is
    // large, and we can't change figment's API.
    #![expect(clippy::result_large_err)]

    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };

    use super::*;

    fn load(jail: &mut Jail, yaml: &str) -> Result<GuestInvitesConfig, String> {
        jail.create_file("config.yaml", yaml)
            .map_err(|e| e.to_string())?;
        let figment = Figment::new().merge(Yaml::file("config.yaml"));
        GuestInvitesConfig::extract(&figment).map_err(|e| e.to_string())
    }

    #[test]
    fn defaults() {
        Jail::expect_with(|jail| {
            let config = load(jail, "guest_invites: {}").unwrap();
            assert!(!config.enabled);
            assert_eq!(config.client_room_url, None);
            assert_eq!(config.invite_lifetime.get(), 604_800);
            assert!(config.is_default());
            Ok(())
        });
    }

    #[test]
    fn enabled_requires_client_room_url() {
        Jail::expect_with(|jail| {
            let error = load(jail, "guest_invites: { enabled: true }").unwrap_err();
            assert!(error.contains("client_room_url"), "{error}");

            let config = load(
                jail,
                r"
                    guest_invites:
                      enabled: true
                      client_room_url: https://app.example.com/#/room/{room_id}
                      invite_lifetime: 3600
                ",
            )
            .unwrap();
            assert!(config.enabled);
            assert_eq!(config.invite_lifetime.get(), 3600);
            Ok(())
        });
    }

    #[test]
    fn invite_lifetime_must_be_positive() {
        Jail::expect_with(|jail| {
            for lifetime in ["0", "-1", "4294967296"] {
                let error = load(
                    jail,
                    &format!("guest_invites: {{ invite_lifetime: {lifetime} }}"),
                )
                .unwrap_err();
                assert!(error.contains("invite_lifetime"), "{error}");
            }
            Ok(())
        });
    }

    #[test]
    fn client_room_url_requires_room_id() {
        Jail::expect_with(|jail| {
            for enabled in [true, false] {
                let error = load(
                    jail,
                    &format!(
                        "guest_invites: {{ enabled: {enabled}, client_room_url: 'https://app.example.com/' }}"
                    ),
                )
                .unwrap_err();
                assert!(error.contains("{room_id}"), "{error}");
            }
            Ok(())
        });
    }

    #[test]
    fn client_room_url_must_be_absolute() {
        Jail::expect_with(|jail| {
            for url in [
                "app.example.com/#/room/{room_id}",
                "localhost:8080/#/room/{room_id}",
                "ftp://app.example.com/#/room/{room_id}",
                "https:/#/room/{room_id}",
            ] {
                let error = load(
                    jail,
                    &format!("guest_invites: {{ client_room_url: '{url}' }}"),
                )
                .unwrap_err();
                assert!(
                    error.contains("absolute HTTP or HTTPS URL"),
                    "{url}: {error}"
                );
            }
            Ok(())
        });
    }
}
