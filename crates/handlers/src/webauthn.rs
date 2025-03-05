// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder, prelude::PasskeyRegistration};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ChallengeState {
    Registration(PasskeyRegistration),
}

/// Builds a webauthn instance.
///
/// # Errors
/// If the public base url doesn't have a host or the webauthn configuration is
/// invalid
pub fn get_webauthn(public_base: &Url) -> Result<Webauthn> {
    let host = public_base
        .host_str()
        .context("Public base doesn't have a host")?;

    Ok(WebauthnBuilder::new(host, public_base)?
        .allow_any_port(host == "localhost") // Useful for testing locally. Should it be configurable for actual deployments?
        .build()?)
}
