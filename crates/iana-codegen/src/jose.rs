// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use serde::Deserialize;

use crate::{
    EnumEntry,
    traits::{Section, s},
};

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum Usage {
    #[serde(rename = "alg")]
    Alg,
    #[serde(rename = "enc")]
    Enc,
    #[serde(rename = "JWK")]
    Jwk,
}

#[derive(Debug, Deserialize)]
enum Requirements {
    Required,
    #[serde(rename = "Recommended+")]
    RecommendedPlus,
    Recommended,
    #[serde(rename = "Recommended-")]
    RecommendedMinus,
    Optional,
    Prohibited,
    Deprecated,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebEncryptionSignatureAlgorithm {
    #[serde(rename = "Algorithm Name")]
    name: String,
    #[serde(rename = "Algorithm Description")]
    description: String,
    #[serde(rename = "Algorithm Usage Location(s)")]
    usage: Usage,
    #[serde(rename = "JOSE Implementation Requirements")]
    requirements: Requirements,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
    #[serde(rename = "Algorithm Analysis Document(s)")]
    analysis: String,
}

impl EnumEntry for WebEncryptionSignatureAlgorithm {
    const URL: &'static str =
        "http://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv";
    const SECTIONS: &'static [Section] = &[
        s(
            "JsonWebSignatureAlg",
            r#"JSON Web Signature "alg" parameter"#,
        ),
        s(
            "JsonWebEncryptionAlg",
            r#"JSON Web Encryption "alg" parameter"#,
        ),
        s(
            "JsonWebEncryptionEnc",
            r#"JSON Web Encryption "enc" parameter"#,
        ),
    ];

    fn key(&self) -> Option<&'static str> {
        match self.usage {
            Usage::Alg => {
                // RFC7518 has one for signature algs and one for encryption algs. The other two
                // RFCs are additional Elliptic curve signature algs
                if self.reference.contains("RFC7518, Section 3")
                    || self.reference.contains("RFC8037")
                    || self.reference.contains("RFC8812")
                    || (self
                        .reference
                        .contains("RFC-ietf-jose-fully-specified-algorithms")
                        && self.reference.contains("Section 2"))
                {
                    Some("JsonWebSignatureAlg")
                } else if self.reference.contains("RFC7518, Section 4")
                    || self.reference.contains("WebCryptoAPI")
                    || (self
                        .reference
                        .contains("RFC-ietf-jose-fully-specified-algorithms")
                        && self.reference.contains("Section 3"))
                {
                    Some("JsonWebEncryptionAlg")
                } else {
                    tracing::warn!("Unknown reference {} for JWA", self.reference);
                    None
                }
            }
            Usage::Enc => Some("JsonWebEncryptionEnc"),
            Usage::Jwk => None,
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebEncryptionCompressionAlgorithm {
    #[serde(rename = "Compression Algorithm Value")]
    value: String,
    #[serde(rename = "Compression Algorithm Description")]
    description: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebEncryptionCompressionAlgorithm {
    const URL: &'static str =
        "http://www.iana.org/assignments/jose/web-encryption-compression-algorithms.csv";
    const SECTIONS: &'static [Section] = &[s(
        "JsonWebEncryptionCompressionAlgorithm",
        "JSON Web Encryption Compression Algorithm",
    )];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebEncryptionCompressionAlgorithm")
    }

    fn name(&self) -> &str {
        &self.value
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyType {
    #[serde(rename = "\"kty\" Parameter Value")]
    value: String,
    #[serde(rename = "Key Type Description")]
    description: String,
    #[serde(rename = "JOSE Implementation Requirements")]
    requirements: Requirements,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyType {
    const URL: &'static str = "http://www.iana.org/assignments/jose/web-key-types.csv";
    const SECTIONS: &'static [Section] = &[s("JsonWebKeyType", "JSON Web Key Type")];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebKeyType")
    }

    fn name(&self) -> &str {
        &self.value
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyEllipticCurve {
    #[serde(rename = "Curve Name")]
    name: String,
    #[serde(rename = "Curve Description")]
    description: String,
    #[serde(rename = "JOSE Implementation Requirements")]
    requirements: Requirements,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyEllipticCurve {
    const URL: &'static str = "http://www.iana.org/assignments/jose/web-key-elliptic-curve.csv";
    const SECTIONS: &'static [Section] = &[
        s(
            "JsonWebKeyEcEllipticCurve",
            "JSON Web Key EC Elliptic Curve",
        ),
        s(
            "JsonWebKeyOkpEllipticCurve",
            "JSON Web Key OKP Elliptic Curve",
        ),
    ];

    fn key(&self) -> Option<&'static str> {
        if self.name.starts_with("P-") || self.name == "secp256k1" {
            Some("JsonWebKeyEcEllipticCurve")
        } else {
            Some("JsonWebKeyOkpEllipticCurve")
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyUse {
    #[serde(rename = "Use Member Value")]
    value: String,
    #[serde(rename = "Use Description")]
    description: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyUse {
    const URL: &'static str = "http://www.iana.org/assignments/jose/web-key-use.csv";
    const SECTIONS: &'static [Section] = &[s("JsonWebKeyUse", "JSON Web Key Use")];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebKeyUse")
    }

    fn name(&self) -> &str {
        &self.value
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyOperation {
    #[serde(rename = "Key Operation Value")]
    name: String,
    #[serde(rename = "Key Operation Description")]
    description: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyOperation {
    const URL: &'static str = "http://www.iana.org/assignments/jose/web-key-operations.csv";
    const SECTIONS: &'static [Section] = &[s("JsonWebKeyOperation", "JSON Web Key Operation")];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebKeyOperation")
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}
