// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use serde::Deserialize;

use crate::{
    EnumEntry,
    traits::{Section, s},
};

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AccessTokenType {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Additional Token Endpoint Response Parameters")]
    additional_parameters: String,
    #[serde(rename = "HTTP Authentication Scheme(s)")]
    http_schemes: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for AccessTokenType {
    const URL: &'static str = "http://www.iana.org/assignments/oauth-parameters/token-types.csv";
    const SECTIONS: &'static [Section] = &[s("OAuthAccessTokenType", "OAuth Access Token Type")];

    fn key(&self) -> Option<&'static str> {
        Some("OAuthAccessTokenType")
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AuthorizationEndpointResponseType {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for AuthorizationEndpointResponseType {
    const URL: &'static str = "http://www.iana.org/assignments/oauth-parameters/endpoint.csv";
    const SECTIONS: &'static [Section] = &[s(
        "OAuthAuthorizationEndpointResponseType",
        "OAuth Authorization Endpoint Response Type",
    )];

    fn key(&self) -> Option<&'static str> {
        Some("OAuthAuthorizationEndpointResponseType")
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct TokenEndpointAuthenticationMethod {
    #[serde(rename = "Token Endpoint Authentication Method Name")]
    name: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct TokenTypeHint {
    #[serde(rename = "Hint Value")]
    name: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for TokenTypeHint {
    const URL: &'static str =
        "http://www.iana.org/assignments/oauth-parameters/token-type-hint.csv";
    const SECTIONS: &'static [Section] = &[s("OAuthTokenTypeHint", "OAuth Token Type Hint")];

    fn key(&self) -> Option<&'static str> {
        Some("OAuthTokenTypeHint")
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl EnumEntry for TokenEndpointAuthenticationMethod {
    const URL: &'static str =
        "http://www.iana.org/assignments/oauth-parameters/token-endpoint-auth-method.csv";
    const SECTIONS: &'static [Section] = &[s(
        "OAuthClientAuthenticationMethod",
        "OAuth Token Endpoint Authentication Method",
    )];

    fn key(&self) -> Option<&'static str> {
        Some("OAuthClientAuthenticationMethod")
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct PkceCodeChallengeMethod {
    #[serde(rename = "Code Challenge Method Parameter Name")]
    name: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for PkceCodeChallengeMethod {
    const URL: &'static str =
        "http://www.iana.org/assignments/oauth-parameters/pkce-code-challenge-method.csv";
    const SECTIONS: &'static [Section] =
        &[s("PkceCodeChallengeMethod", "PKCE Code Challenge Method")];

    fn key(&self) -> Option<&'static str> {
        Some("PkceCodeChallengeMethod")
    }

    fn name(&self) -> &str {
        &self.name
    }
}
