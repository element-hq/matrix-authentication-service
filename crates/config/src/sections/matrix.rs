// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use rand::{
    distributions::{Alphanumeric, DistString},
    Rng,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use url::Url;

use super::ConfigurationSection;

fn default_homeserver() -> String {
    "localhost:8008".to_owned()
}

fn default_endpoint() -> Url {
    Url::parse("http://localhost:8008/").unwrap()
}

/// Configuration related to the Matrix homeserver
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatrixConfig {
    /// The server name of the homeserver.
    #[serde(default = "default_homeserver")]
    pub homeserver: String,

    /// Shared secret to use for calls to the admin API
    pub secret: String,

    /// The base URL of the homeserver's client API
    #[serde(default = "default_endpoint")]
    pub endpoint: Url,
}

impl ConfigurationSection for MatrixConfig {
    const PATH: Option<&'static str> = Some("matrix");
}

impl MatrixConfig {
    pub(crate) fn generate<R>(mut rng: R) -> Self
    where
        R: Rng + Send,
    {
        Self {
            homeserver: default_homeserver(),
            secret: Alphanumeric.sample_string(&mut rng, 32),
            endpoint: default_endpoint(),
        }
    }

    pub(crate) fn test() -> Self {
        Self {
            homeserver: default_homeserver(),
            secret: "test".to_owned(),
            endpoint: default_endpoint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        providers::{Format, Yaml},
        Figment, Jail,
    };

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    matrix:
                      homeserver: matrix.org
                      secret: test
                ",
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<MatrixConfig>("matrix")?;

            assert_eq!(&config.homeserver, "matrix.org");
            assert_eq!(&config.secret, "test");

            Ok(())
        });
    }
}
