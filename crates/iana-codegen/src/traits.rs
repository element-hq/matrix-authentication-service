// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context;
use async_trait::async_trait;
use convert_case::{Case, Casing};
use serde::de::DeserializeOwned;

use super::Client;

#[derive(Debug, Clone)]
pub struct Section {
    pub key: &'static str,
    pub doc: &'static str,
    pub url: Option<&'static str>,
}

#[must_use]
pub const fn s(key: &'static str, doc: &'static str) -> Section {
    Section {
        key,
        doc,
        url: None,
    }
}

#[derive(Debug)]
pub struct EnumMember {
    pub value: String,
    pub description: Option<String>,
    pub enum_name: String,
}

#[async_trait]
pub trait EnumEntry: DeserializeOwned + Send + Sync {
    const URL: &'static str;
    const SECTIONS: &'static [Section];

    #[must_use]
    fn sections() -> Vec<Section> {
        Self::SECTIONS
            .iter()
            .map(|s| Section {
                url: Some(Self::URL),
                ..*s
            })
            .collect()
    }

    fn key(&self) -> Option<&'static str>;
    fn name(&self) -> &str;
    fn description(&self) -> Option<&str> {
        None
    }
    fn enum_name(&self) -> String {
        // Do the case transformation twice to have "N_A" turned to "Na" instead of "NA"
        self.name()
            .replace('+', "_")
            .to_case(Case::Pascal)
            .to_case(Case::Pascal)
    }

    async fn fetch(client: &Client) -> anyhow::Result<Vec<(&'static str, EnumMember)>> {
        tracing::info!("Fetching CSV");

        #[expect(
            clippy::disallowed_methods,
            reason = "we don't use send_traced in the codegen"
        )]
        let response = client
            .get(Self::URL)
            .header("User-Agent", "mas-iana-codegen/0.1")
            .send()
            .await
            .context(format!("can't the CSV at {}", Self::URL))?;

        let status = response.status();
        anyhow::ensure!(status.is_success(), "HTTP status code is not 200: {status}");

        let body = response
            .text()
            .await
            .context(format!("can't the CSV body at {}", Self::URL))?;

        let parsed: Result<Vec<_>, _> = csv::Reader::from_reader(body.as_bytes())
            .into_deserialize()
            .filter_map(|item: Result<Self, _>| {
                item.map(|item| {
                    if item
                        .description()
                        .is_some_and(|desc| desc.contains("TEMPORARY"))
                    {
                        return None;
                    }

                    item.key().map(|key| {
                        (
                            key,
                            EnumMember {
                                value: item.name().to_owned(),
                                description: item.description().map(ToOwned::to_owned),
                                enum_name: item.enum_name(),
                            },
                        )
                    })
                })
                .transpose()
            })
            .collect();

        Ok(parsed.context(format!("can't parse the CSV at {}", Self::URL))?)
    }
}
