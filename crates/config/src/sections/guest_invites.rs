// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};
use url::Url;

use crate::ConfigurationSection;

/// Configuration section for inviting guests to rooms by email
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub struct GuestInvitesConfig {
    /// The client URL to send invitees to once they are signed in, with
    /// `{room_id}` standing for the room ID, e.g.
    /// `https://app.element.io/#/room/{room_id}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_room_url: Option<String>,
}

impl GuestInvitesConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        self.client_room_url.is_none()
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
            assert_eq!(config.client_room_url, None);
            assert!(config.is_default());
            Ok(())
        });
    }

    #[test]
    fn client_room_url_requires_room_id() {
        Jail::expect_with(|jail| {
            let error = load(
                jail,
                "guest_invites: { client_room_url: 'https://app.example.com/' }",
            )
            .unwrap_err();
            assert!(error.contains("{room_id}"), "{error}");
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
