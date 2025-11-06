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

use super::ParametersInfo;
use crate::{base64::Base64UrlNoPad, jwk::Thumbprint};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kty")]
pub enum JsonWebKeyPublicParameters {
    #[serde(rename = "RSA")]
    Rsa(RsaPublicParameters),

    #[serde(rename = "EC")]
    Ec(EcPublicParameters),

    #[serde(rename = "OKP")]
    Okp(OkpPublicParameters),
}

impl JsonWebKeyPublicParameters {
    #[must_use]
    pub const fn rsa(&self) -> Option<&RsaPublicParameters> {
        match self {
            Self::Rsa(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn ec(&self) -> Option<&EcPublicParameters> {
        match self {
            Self::Ec(params) => Some(params),
            _ => None,
        }
    }

    #[must_use]
    pub const fn okp(&self) -> Option<&OkpPublicParameters> {
        match self {
            Self::Okp(params) => Some(params),
            _ => None,
        }
    }
}

impl Thumbprint for JsonWebKeyPublicParameters {
    fn thumbprint_prehashed(&self) -> String {
        match self {
            JsonWebKeyPublicParameters::Rsa(RsaPublicParameters { n, e }) => {
                format!("{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}")
            }
            JsonWebKeyPublicParameters::Ec(EcPublicParameters { crv, x, y }) => {
                format!("{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")
            }
            JsonWebKeyPublicParameters::Okp(OkpPublicParameters { crv, x }) => {
                format!("{{\"crv\":\"{crv}\",\"kty\":\"OKP\",\"x\":\"{x}\"}}")
            }
        }
    }
}

impl ParametersInfo for JsonWebKeyPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        match self {
            Self::Rsa(_) => JsonWebKeyType::Rsa,
            Self::Ec(_) => JsonWebKeyType::Ec,
            Self::Okp(_) => JsonWebKeyType::Okp,
        }
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        match self {
            JsonWebKeyPublicParameters::Rsa(p) => p.possible_algs(),
            JsonWebKeyPublicParameters::Ec(p) => p.possible_algs(),
            JsonWebKeyPublicParameters::Okp(p) => p.possible_algs(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RsaPublicParameters {
    #[schemars(with = "String")]
    n: Base64UrlNoPad,

    #[schemars(with = "String")]
    e: Base64UrlNoPad,
}

impl ParametersInfo for RsaPublicParameters {
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

impl RsaPublicParameters {
    pub const fn new(n: Base64UrlNoPad, e: Base64UrlNoPad) -> Self {
        Self { n, e }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EcPublicParameters {
    pub(crate) crv: JsonWebKeyEcEllipticCurve,

    #[schemars(with = "String")]
    x: Base64UrlNoPad,

    #[schemars(with = "String")]
    y: Base64UrlNoPad,
}

impl EcPublicParameters {
    pub const fn new(crv: JsonWebKeyEcEllipticCurve, x: Base64UrlNoPad, y: Base64UrlNoPad) -> Self {
        Self { crv, x, y }
    }
}

impl ParametersInfo for EcPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Ec
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        match &self.crv {
            JsonWebKeyEcEllipticCurve::P256 => &[JsonWebSignatureAlg::Es256],
            JsonWebKeyEcEllipticCurve::P384 => &[JsonWebSignatureAlg::Es384],
            JsonWebKeyEcEllipticCurve::P521 => &[JsonWebSignatureAlg::Es512],
            JsonWebKeyEcEllipticCurve::Secp256K1 => &[JsonWebSignatureAlg::Es256K],
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OkpPublicParameters {
    crv: JsonWebKeyOkpEllipticCurve,

    #[schemars(with = "String")]
    x: Base64UrlNoPad,
}

impl ParametersInfo for OkpPublicParameters {
    fn kty(&self) -> JsonWebKeyType {
        JsonWebKeyType::Okp
    }

    fn possible_algs(&self) -> &[JsonWebSignatureAlg] {
        &[JsonWebSignatureAlg::EdDsa]
    }
}

impl OkpPublicParameters {
    pub const fn new(crv: JsonWebKeyOkpEllipticCurve, x: Base64UrlNoPad) -> Self {
        Self { crv, x }
    }
}

mod rsa_impls {
    use rsa::{BigUint, RsaPublicKey, traits::PublicKeyParts};

    use super::{JsonWebKeyPublicParameters, RsaPublicParameters};
    use crate::base64::Base64UrlNoPad;

    impl From<RsaPublicKey> for JsonWebKeyPublicParameters {
        fn from(key: RsaPublicKey) -> Self {
            Self::from(&key)
        }
    }

    impl From<&RsaPublicKey> for JsonWebKeyPublicParameters {
        fn from(key: &RsaPublicKey) -> Self {
            Self::Rsa(key.into())
        }
    }

    impl From<RsaPublicKey> for RsaPublicParameters {
        fn from(key: RsaPublicKey) -> Self {
            Self::from(&key)
        }
    }

    impl From<&RsaPublicKey> for RsaPublicParameters {
        fn from(key: &RsaPublicKey) -> Self {
            Self {
                n: Base64UrlNoPad::new(key.n().to_bytes_be()),
                e: Base64UrlNoPad::new(key.e().to_bytes_be()),
            }
        }
    }

    impl TryFrom<RsaPublicParameters> for RsaPublicKey {
        type Error = rsa::errors::Error;
        fn try_from(value: RsaPublicParameters) -> Result<Self, Self::Error> {
            (&value).try_into()
        }
    }

    impl TryFrom<&RsaPublicParameters> for RsaPublicKey {
        type Error = rsa::errors::Error;
        fn try_from(value: &RsaPublicParameters) -> Result<Self, Self::Error> {
            let n = BigUint::from_bytes_be(value.n.as_bytes());
            let e = BigUint::from_bytes_be(value.e.as_bytes());
            let key = RsaPublicKey::new(n, e)?;
            Ok(key)
        }
    }
}

mod ec_impls {
    use digest::typenum::Unsigned;
    use ecdsa::EncodedPoint;
    use elliptic_curve::{
        AffinePoint, FieldBytes, PublicKey,
        sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    };

    use super::{super::JwkEcCurve, EcPublicParameters, JsonWebKeyPublicParameters};
    use crate::base64::Base64UrlNoPad;

    impl<C> TryFrom<&EcPublicParameters> for PublicKey<C>
    where
        C: elliptic_curve::CurveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize + Unsigned,
    {
        type Error = elliptic_curve::Error;
        fn try_from(value: &EcPublicParameters) -> Result<Self, Self::Error> {
            let x = value
                .x
                .as_bytes()
                .get(..C::FieldBytesSize::USIZE)
                .ok_or(elliptic_curve::Error)?;
            let y = value
                .y
                .as_bytes()
                .get(..C::FieldBytesSize::USIZE)
                .ok_or(elliptic_curve::Error)?;

            let x = FieldBytes::<C>::from_slice(x);
            let y = FieldBytes::<C>::from_slice(y);
            let pubkey = EncodedPoint::<C>::from_affine_coordinates(x, y, false);
            let pubkey: Option<_> = PublicKey::from_encoded_point(&pubkey).into();
            pubkey.ok_or(elliptic_curve::Error)
        }
    }

    impl<C> From<PublicKey<C>> for JsonWebKeyPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: PublicKey<C>) -> Self {
            (&key).into()
        }
    }

    impl<C> From<&PublicKey<C>> for JsonWebKeyPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: &PublicKey<C>) -> Self {
            Self::Ec(key.into())
        }
    }

    impl<C> From<PublicKey<C>> for EcPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: PublicKey<C>) -> Self {
            (&key).into()
        }
    }

    impl<C> From<&PublicKey<C>> for EcPublicParameters
    where
        C: elliptic_curve::CurveArithmetic + JwkEcCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        C::FieldBytesSize: ModulusSize,
    {
        fn from(key: &PublicKey<C>) -> Self {
            let point = key.to_encoded_point(false);
            let Coordinates::Uncompressed { x, y } = point.coordinates() else {
                unreachable!()
            };
            EcPublicParameters {
                crv: C::CRV,
                x: Base64UrlNoPad::new(x.to_vec()),
                y: Base64UrlNoPad::new(y.to_vec()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thumbprint_rfc_example() {
        // From https://www.rfc-editor.org/rfc/rfc7638.html#section-3.1
        let n = Base64UrlNoPad::parse(
            "\
            0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
            VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\
            4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\
            W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\
            1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\
            aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        )
        .unwrap();
        let e = Base64UrlNoPad::parse("AQAB").unwrap();

        let jwkpps = JsonWebKeyPublicParameters::Rsa(RsaPublicParameters { n, e });

        assert_eq!(
            jwkpps.thumbprint_sha256_base64(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
