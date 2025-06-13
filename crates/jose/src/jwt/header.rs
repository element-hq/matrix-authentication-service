// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use mas_iana::jose::JsonWebSignatureAlg;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::{Base64, base64::Base64UrlNoPad, jwk::PublicJsonWebKey};

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JsonWebSignatureHeader {
    alg: JsonWebSignatureAlg,

    #[serde(default)]
    jku: Option<Url>,

    #[serde(default)]
    jwk: Option<Box<PublicJsonWebKey>>,

    #[serde(default)]
    kid: Option<String>,

    #[serde(default)]
    x5u: Option<Url>,

    #[serde(default)]
    x5c: Option<Vec<Base64>>,

    #[serde(default)]
    x5t: Option<Base64UrlNoPad>,

    #[serde(default, rename = "x5t#S256")]
    x5t_s256: Option<Base64UrlNoPad>,

    #[serde(default)]
    typ: Option<String>,

    #[serde(default)]
    cty: Option<String>,

    #[serde(default)]
    crit: Option<Vec<String>>,
}

impl JsonWebSignatureHeader {
    #[must_use]
    pub fn new(alg: JsonWebSignatureAlg) -> Self {
        Self {
            alg,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            typ: None,
            cty: None,
            crit: None,
        }
    }

    #[must_use]
    pub const fn alg(&self) -> &JsonWebSignatureAlg {
        &self.alg
    }

    #[must_use]
    pub const fn jku(&self) -> Option<&Url> {
        self.jku.as_ref()
    }

    #[must_use]
    pub fn with_jku(mut self, jku: Url) -> Self {
        self.jku = Some(jku);
        self
    }

    #[must_use]
    pub const fn jwk(&self) -> Option<&PublicJsonWebKey> {
        // Can't use as_deref because it's not a const fn
        match &self.jwk {
            Some(jwk) => Some(jwk),
            None => None,
        }
    }

    #[must_use]
    pub fn with_jwk(mut self, jwk: PublicJsonWebKey) -> Self {
        self.jwk = Some(Box::new(jwk));
        self
    }

    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    #[must_use]
    pub fn with_typ(mut self, typ: String) -> Self {
        self.typ = Some(typ);
        self
    }

    #[must_use]
    pub fn crit(&self) -> Option<&[String]> {
        self.crit.as_deref()
    }

    #[must_use]
    pub fn with_crit(mut self, crit: Vec<String>) -> Self {
        self.crit = Some(crit);
        self
    }
}
