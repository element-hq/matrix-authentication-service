// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use mas_iana::jose::{
    JsonWebKeyEcEllipticCurve, JsonWebKeyOkpEllipticCurve, JsonWebKeyType, JsonWebSignatureAlg,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{ParametersInfo, public_parameters::JsonWebKeyPublicParameters};
use crate::base64::Base64UrlNoPad;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kty")]
pub enum JsonWebKeyPrivateParameters {
    #[serde(rename = "oct")]
    Oct(OctPrivateParameters),

    #[serde(rename = "RSA")]
    Rsa(RsaPrivateParameters),

    #[serde(rename = "EC")]
    Ec(EcPrivateParameters),

    #[serde(rename = "OKP")]
    Okp(OkpPrivateParameters),
}

impl JsonWebKeyPrivateParameters {
    #[must_use]
    pub const fn oct(&self) -> Option<&OctPrivateParameters> {
        match self {
            Self::Oct(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn rsa(&self) -> Option<&RsaPrivateParameters> {
        match self {
            Self::Rsa(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn ec(&self) -> Option<&EcPrivateParameters> {
        match self {
            Self::Ec(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn okp(&self) -> Option<&OkpPrivateParameters> {
        match self {
            Self::Okp(params) => Some(params),
            _ => None,
        }
    }
}

impl ParametersInfo for JsonWebKeyPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        match self {
            Self::Oct(_) => JsonWebKeyType::Oct,
            Self::Rsa(_) => JsonWebKeyType::Rsa,
            Self::Ec(_) => JsonWebKeyType::Ec,
            Self::Okp(_) => JsonWebKeyType::Okp,
        }
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        match self {
            JsonWebKeyPrivateParameters::Oct(p) => p.possible_algs(),
            JsonWebKeyPrivateParameters::Rsa(p) => p.possible_algs(),
            JsonWebKeyPrivateParameters::Ec(p) => p.possible_algs(),
            JsonWebKeyPrivateParameters::Okp(p) => p.possible_algs(),
        }
    }
}

#[derive(Debug, Error)]
#[error("can't extract a public key out of a symetric key")]
pub struct SymetricKeyError;

impl TryFrom<JsonWebKeyPrivateParameters> for JsonWebKeyPublicParameters {
    type Error = SymetricKeyError;

    fn try_from(value: JsonWebKeyPrivateParameters) -> Result<Self, Self::Error> {
        match value {
            JsonWebKeyPrivateParameters::Oct(_) => Err(SymetricKeyError),
            JsonWebKeyPrivateParameters::Rsa(p) => Ok(JsonWebKeyPublicParameters::Rsa(p.into())),
            JsonWebKeyPrivateParameters::Ec(p) => Ok(JsonWebKeyPublicParameters::Ec(p.into())),
            JsonWebKeyPrivateParameters::Okp(p) => Ok(JsonWebKeyPublicParameters::Okp(p.into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OctPrivateParameters {
    /// Key Value
    #[schemars(with = "String")]
    k: Base64UrlNoPad,
}

impl ParametersInfo for OctPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Oct
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        &[
            JsonWebSignatureAlg::Hs256,
            JsonWebSignatureAlg::Hs384,
            JsonWebSignatureAlg::Hs512,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RsaPrivateParameters {
    /// Modulus
    #[schemars(with = "String")]
    n: Base64UrlNoPad,

    /// Exponent
    #[schemars(with = "String")]
    e: Base64UrlNoPad,

    /// Private Exponent
    #[schemars(with = "String")]
    d: Base64UrlNoPad,

    /// First Prime Factor
    #[schemars(with = "String")]
    p: Base64UrlNoPad,

    /// Second Prime Factor
    #[schemars(with = "String")]
    q: Base64UrlNoPad,

    /// First Factor CRT Exponent
    #[schemars(with = "String")]
    dp: Base64UrlNoPad,

    /// Second Factor CRT Exponent
    #[schemars(with = "String")]
    dq: Base64UrlNoPad,

    /// First CRT Coefficient
    #[schemars(with = "String")]
    qi: Base64UrlNoPad,

    /// Other Primes Info
    #[serde(skip_serializing_if = "Option::is_none")]
    oth: Option<Vec<RsaOtherPrimeInfo>>,
}

impl ParametersInfo for RsaPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Rsa
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        &[
            JsonWebSignatureAlg::Rs256,
            JsonWebSignatureAlg::Rs384,
            JsonWebSignatureAlg::Rs512,
            JsonWebSignatureAlg::Ps256,
            JsonWebSignatureAlg::Ps384,
            JsonWebSignatureAlg::Ps512,
        ]
    }
}

impl From<RsaPrivateParameters> for super::public_parameters::RsaPublicParameters {
    fn from(params: RsaPrivateParameters) -> Self {
        Self::new(params.n, params.e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct RsaOtherPrimeInfo {
    /// Prime Factor
    #[schemars(with = "String")]
    r: Base64UrlNoPad,

    /// Factor CRT Exponent
    #[schemars(with = "String")]
    d: Base64UrlNoPad,

    /// Factor CRT Coefficient
    #[schemars(with = "String")]
    t: Base64UrlNoPad,
}

mod rsa_impls {
    use rsa::{BigUint, RsaPrivateKey};

    use super::RsaPrivateParameters;

    impl TryFrom<RsaPrivateParameters> for RsaPrivateKey {
        type Error = rsa::errors::Error;
        fn try_from(value: RsaPrivateParameters) -> Result<Self, Self::Error> {
            Self::try_from(&value)
        }
    }

    impl TryFrom<&RsaPrivateParameters> for RsaPrivateKey {
        type Error = rsa::errors::Error;

        #[allow(clippy::many_single_char_names)]
        fn try_from(value: &RsaPrivateParameters) -> Result<Self, Self::Error> {
            let n = BigUint::from_bytes_be(value.n.as_bytes());
            let e = BigUint::from_bytes_be(value.e.as_bytes());
            let d = BigUint::from_bytes_be(value.d.as_bytes());

            let primes = [&value.p, &value.q]
                .into_iter()
                .chain(value.oth.iter().flatten().map(|o| &o.r))
                .map(|i| BigUint::from_bytes_be(i.as_bytes()))
                .collect();

            let key = RsaPrivateKey::from_components(n, e, d, primes)?;

            key.validate()?;

            Ok(key)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EcPrivateParameters {
    pub(crate) crv: JsonWebKeyEcEllipticCurve,

    #[schemars(with = "String")]
    x: Base64UrlNoPad,

    #[schemars(with = "String")]
    y: Base64UrlNoPad,

    #[schemars(with = "String")]
    d: Base64UrlNoPad,
}

impl ParametersInfo for EcPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Ec
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        match self.crv {
            JsonWebKeyEcEllipticCurve::P256 => &[JsonWebSignatureAlg::Es256],
            JsonWebKeyEcEllipticCurve::P384 => &[JsonWebSignatureAlg::Es384],
            JsonWebKeyEcEllipticCurve::P521 => &[JsonWebSignatureAlg::Es512],
            JsonWebKeyEcEllipticCurve::Secp256K1 => &[JsonWebSignatureAlg::Es256K],
            _ => &[],
        }
    }
}

impl From<EcPrivateParameters> for super::public_parameters::EcPublicParameters {
    fn from(params: EcPrivateParameters) -> Self {
        Self::new(params.crv, params.x, params.y)
    }
}

mod ec_impls {
    use elliptic_curve::{
        AffinePoint, Curve, SecretKey,
        sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    };

    use super::{super::JwkEcCurve, EcPrivateParameters};
    use crate::base64::Base64UrlNoPad;

    impl<C> TryFrom<EcPrivateParameters> for SecretKey<C>
    where
        C: Curve,
    {
        type Error = elliptic_curve::Error;
        fn try_from(value: EcPrivateParameters) -> Result<Self, Self::Error> {
            Self::try_from(&value)
        }
    }

    impl<C> TryFrom<&EcPrivateParameters> for SecretKey<C>
    where
        C: Curve,
    {
        type Error = elliptic_curve::Error;

        fn try_from(value: &EcPrivateParameters) -> Result<Self, Self::Error> {
            SecretKey::from_slice(value.d.as_bytes())
        }
    }

    impl<C> From<SecretKey<C>> for EcPrivateParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: SecretKey<C>) -> Self {
            (&key).into()
        }
    }

    impl<C> From<&SecretKey<C>> for EcPrivateParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: &SecretKey<C>) -> Self {
            let point = key.public_key().to_encoded_point(false);
            let Coordinates::Uncompressed { x, y } = point.coordinates() else {
                unreachable!()
            };
            let d = key.to_bytes();
            EcPrivateParameters {
                crv: C::CRV,
                x: Base64UrlNoPad::new(x.to_vec()),
                y: Base64UrlNoPad::new(y.to_vec()),
                d: Base64UrlNoPad::new(d.to_vec()),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OkpPrivateParameters {
    crv: JsonWebKeyOkpEllipticCurve,

    #[schemars(with = "String")]
    x: Base64UrlNoPad,
}

impl ParametersInfo for OkpPrivateParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Okp
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        &[JsonWebSignatureAlg::EdDsa]
    }
}

impl From<OkpPrivateParameters> for super::public_parameters::OkpPublicParameters {
    fn from(params: OkpPrivateParameters) -> Self {
        Self::new(params.crv, params.x)
    }
}
