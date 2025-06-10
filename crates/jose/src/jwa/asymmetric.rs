// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use digest::Digest;
use mas_iana::jose::{JsonWebKeyEcEllipticCurve, JsonWebSignatureAlg};
use sha2::{Sha256, Sha384, Sha512};
use signature::rand_core::CryptoRngCore;
use thiserror::Error;

use super::signature::Signature;
use crate::jwk::{JsonWebKeyPrivateParameters, JsonWebKeyPublicParameters};

#[derive(Debug, Error)]
pub enum AsymmetricKeyFromJwkError {
    #[error("Invalid RSA parameters")]
    Rsa {
        #[from]
        inner: rsa::errors::Error,
    },

    #[error("Invalid Elliptic Curve parameters")]
    EllipticCurve {
        #[from]
        inner: elliptic_curve::Error,
    },

    #[error("Unsupported algorithm {alg}")]
    UnsupportedAlgorithm { alg: JsonWebSignatureAlg },

    #[error("Key not suitable for algorithm {alg}")]
    KeyNotSuitable { alg: JsonWebSignatureAlg },
}

/// An enum of all supported asymmetric signature algorithms verifying keys
#[non_exhaustive]
pub enum AsymmetricSigningKey {
    Rs256(super::Rs256SigningKey),
    Rs384(super::Rs384SigningKey),
    Rs512(super::Rs512SigningKey),
    Ps256(super::Ps256SigningKey),
    Ps384(super::Ps384SigningKey),
    Ps512(super::Ps512SigningKey),
    Es256(super::Es256SigningKey),
    Es384(super::Es384SigningKey),
    Es256K(super::Es256KSigningKey),
}

impl AsymmetricSigningKey {
    /// Create a new signing key with the RS256 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn rs256(key: rsa::RsaPrivateKey) -> Self {
        Self::Rs256(rsa::pkcs1v15::SigningKey::new(key))
    }

    /// Create a new signing key with the RS384 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn rs384(key: rsa::RsaPrivateKey) -> Self {
        Self::Rs384(rsa::pkcs1v15::SigningKey::new(key))
    }

    /// Create a new signing key with the RS512 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn rs512(key: rsa::RsaPrivateKey) -> Self {
        Self::Rs512(rsa::pkcs1v15::SigningKey::new(key))
    }

    /// Create a new signing key with the PS256 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn ps256(key: rsa::RsaPrivateKey) -> Self {
        Self::Ps256(rsa::pss::SigningKey::new_with_salt_len(
            key,
            Sha256::output_size(),
        ))
    }

    /// Create a new signing key with the PS384 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn ps384(key: rsa::RsaPrivateKey) -> Self {
        Self::Ps384(rsa::pss::SigningKey::new_with_salt_len(
            key,
            Sha384::output_size(),
        ))
    }

    /// Create a new signing key with the PS512 algorithm from the given RSA
    /// private key.
    #[must_use]
    pub fn ps512(key: rsa::RsaPrivateKey) -> Self {
        Self::Ps512(rsa::pss::SigningKey::new_with_salt_len(
            key,
            Sha512::output_size(),
        ))
    }

    /// Create a new signing key with the ES256 algorithm from the given ECDSA
    /// private key.
    #[must_use]
    pub fn es256(key: elliptic_curve::SecretKey<p256::NistP256>) -> Self {
        Self::Es256(ecdsa::SigningKey::from(key))
    }

    /// Create a new signing key with the ES384 algorithm from the given ECDSA
    /// private key.
    #[must_use]
    pub fn es384(key: elliptic_curve::SecretKey<p384::NistP384>) -> Self {
        Self::Es384(ecdsa::SigningKey::from(key))
    }

    /// Create a new signing key with the ES256K algorithm from the given ECDSA
    /// private key.
    #[must_use]
    pub fn es256k(key: elliptic_curve::SecretKey<k256::Secp256k1>) -> Self {
        Self::Es256K(ecdsa::SigningKey::from(key))
    }

    /// Create a new signing key for the given algorithm from the given private
    /// JWK parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the key parameters are not suitable for the given
    /// algorithm.
    pub fn from_jwk_and_alg(
        params: &JsonWebKeyPrivateParameters,
        alg: &JsonWebSignatureAlg,
    ) -> Result<Self, AsymmetricKeyFromJwkError> {
        match (params, alg) {
            (JsonWebKeyPrivateParameters::Rsa(params), alg) => match alg {
                JsonWebSignatureAlg::Rs256 => Ok(Self::rs256(params.try_into()?)),
                JsonWebSignatureAlg::Rs384 => Ok(Self::rs384(params.try_into()?)),
                JsonWebSignatureAlg::Rs512 => Ok(Self::rs512(params.try_into()?)),
                JsonWebSignatureAlg::Ps256 => Ok(Self::ps256(params.try_into()?)),
                JsonWebSignatureAlg::Ps384 => Ok(Self::ps384(params.try_into()?)),
                JsonWebSignatureAlg::Ps512 => Ok(Self::ps512(params.try_into()?)),
                _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
            },

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es256)
                if params.crv == JsonWebKeyEcEllipticCurve::P256 =>
            {
                Ok(Self::es256(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es384)
                if params.crv == JsonWebKeyEcEllipticCurve::P384 =>
            {
                Ok(Self::es384(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es512)
                if params.crv == JsonWebKeyEcEllipticCurve::P521 =>
            {
                Err(AsymmetricKeyFromJwkError::UnsupportedAlgorithm { alg: alg.clone() })
            }

            (JsonWebKeyPrivateParameters::Ec(params), JsonWebSignatureAlg::Es256K)
                if params.crv == JsonWebKeyEcEllipticCurve::Secp256K1 =>
            {
                Ok(Self::es256k(params.try_into()?))
            }

            (JsonWebKeyPrivateParameters::Okp(_params), _) => {
                Err(AsymmetricKeyFromJwkError::UnsupportedAlgorithm { alg: alg.clone() })
            }

            _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
        }
    }
}

impl From<super::Rs256SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Rs256SigningKey) -> Self {
        Self::Rs256(key)
    }
}

impl From<super::Rs384SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Rs384SigningKey) -> Self {
        Self::Rs384(key)
    }
}

impl From<super::Rs512SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Rs512SigningKey) -> Self {
        Self::Rs512(key)
    }
}

impl From<super::Ps256SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Ps256SigningKey) -> Self {
        Self::Ps256(key)
    }
}

impl From<super::Ps384SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Ps384SigningKey) -> Self {
        Self::Ps384(key)
    }
}

impl From<super::Ps512SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Ps512SigningKey) -> Self {
        Self::Ps512(key)
    }
}

impl From<super::Es256SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es256SigningKey) -> Self {
        Self::Es256(key)
    }
}

impl From<super::Es384SigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es384SigningKey) -> Self {
        Self::Es384(key)
    }
}

impl From<super::Es256KSigningKey> for AsymmetricSigningKey {
    fn from(key: super::Es256KSigningKey) -> Self {
        Self::Es256K(key)
    }
}

impl signature::RandomizedSigner<Signature> for AsymmetricSigningKey {
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<Signature, signature::Error> {
        match self {
            Self::Rs256(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Rs384(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Rs512(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Ps256(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Ps384(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Ps512(key) => {
                let signature = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es256(key) => {
                let signature: ecdsa::Signature<_> = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es384(key) => {
                let signature: ecdsa::Signature<_> = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Es256K(key) => {
                let signature: ecdsa::Signature<_> = key.try_sign_with_rng(rng, msg)?;
                Ok(Signature::from_signature(&signature))
            }
        }
    }
}

/// An enum of all supported asymmetric signature algorithms signing keys
#[non_exhaustive]
pub enum AsymmetricVerifyingKey {
    Rs256(super::Rs256VerifyingKey),
    Rs384(super::Rs384VerifyingKey),
    Rs512(super::Rs512VerifyingKey),
    Ps256(super::Ps256VerifyingKey),
    Ps384(super::Ps384VerifyingKey),
    Ps512(super::Ps512VerifyingKey),
    Es256(super::Es256VerifyingKey),
    Es384(super::Es384VerifyingKey),
    Es256K(super::Es256KVerifyingKey),
}

impl AsymmetricVerifyingKey {
    /// Create a new verifying key with the RS256 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn rs256(key: rsa::RsaPublicKey) -> Self {
        Self::Rs256(rsa::pkcs1v15::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the RS384 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn rs384(key: rsa::RsaPublicKey) -> Self {
        Self::Rs384(rsa::pkcs1v15::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the RS512 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn rs512(key: rsa::RsaPublicKey) -> Self {
        Self::Rs512(rsa::pkcs1v15::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the PS256 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn ps256(key: rsa::RsaPublicKey) -> Self {
        Self::Ps256(rsa::pss::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the PS384 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn ps384(key: rsa::RsaPublicKey) -> Self {
        Self::Ps384(rsa::pss::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the PS512 algorithm from the given RSA
    /// public key.
    #[must_use]
    pub fn ps512(key: rsa::RsaPublicKey) -> Self {
        Self::Ps512(rsa::pss::VerifyingKey::new(key))
    }

    /// Create a new verifying key with the ES256 algorithm from the given ECDSA
    /// public key.
    #[must_use]
    pub fn es256(key: elliptic_curve::PublicKey<p256::NistP256>) -> Self {
        Self::Es256(ecdsa::VerifyingKey::from(key))
    }

    /// Create a new verifying key with the ES384 algorithm from the given ECDSA
    /// public key.
    #[must_use]
    pub fn es384(key: elliptic_curve::PublicKey<p384::NistP384>) -> Self {
        Self::Es384(ecdsa::VerifyingKey::from(key))
    }

    /// Create a new verifying key with the ES256K algorithm from the given
    /// ECDSA public key.
    #[must_use]
    pub fn es256k(key: elliptic_curve::PublicKey<k256::Secp256k1>) -> Self {
        Self::Es256K(ecdsa::VerifyingKey::from(key))
    }

    /// Create a new verifying key for the given algorithm from the given public
    /// JWK parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the key parameters are not suitable for the given
    /// algorithm.
    pub fn from_jwk_and_alg(
        params: &JsonWebKeyPublicParameters,
        alg: &JsonWebSignatureAlg,
    ) -> Result<Self, AsymmetricKeyFromJwkError> {
        match (params, alg) {
            (JsonWebKeyPublicParameters::Rsa(params), alg) => match alg {
                JsonWebSignatureAlg::Rs256 => Ok(Self::rs256(params.try_into()?)),
                JsonWebSignatureAlg::Rs384 => Ok(Self::rs384(params.try_into()?)),
                JsonWebSignatureAlg::Rs512 => Ok(Self::rs512(params.try_into()?)),
                JsonWebSignatureAlg::Ps256 => Ok(Self::ps256(params.try_into()?)),
                JsonWebSignatureAlg::Ps384 => Ok(Self::ps384(params.try_into()?)),
                JsonWebSignatureAlg::Ps512 => Ok(Self::ps512(params.try_into()?)),
                _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
            },

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es256)
                if params.crv == JsonWebKeyEcEllipticCurve::P256 =>
            {
                Ok(Self::es256(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es384)
                if params.crv == JsonWebKeyEcEllipticCurve::P384 =>
            {
                Ok(Self::es384(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es512)
                if params.crv == JsonWebKeyEcEllipticCurve::P521 =>
            {
                Err(AsymmetricKeyFromJwkError::UnsupportedAlgorithm { alg: alg.clone() })
            }

            (JsonWebKeyPublicParameters::Ec(params), JsonWebSignatureAlg::Es256K)
                if params.crv == JsonWebKeyEcEllipticCurve::Secp256K1 =>
            {
                Ok(Self::es256k(params.try_into()?))
            }

            (JsonWebKeyPublicParameters::Okp(_params), _) => {
                Err(AsymmetricKeyFromJwkError::UnsupportedAlgorithm { alg: alg.clone() })
            }

            _ => Err(AsymmetricKeyFromJwkError::KeyNotSuitable { alg: alg.clone() }),
        }
    }
}

impl From<super::Rs256VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Rs256VerifyingKey) -> Self {
        Self::Rs256(key)
    }
}

impl From<super::Rs384VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Rs384VerifyingKey) -> Self {
        Self::Rs384(key)
    }
}

impl From<super::Rs512VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Rs512VerifyingKey) -> Self {
        Self::Rs512(key)
    }
}

impl From<super::Ps256VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Ps256VerifyingKey) -> Self {
        Self::Ps256(key)
    }
}

impl From<super::Ps384VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Ps384VerifyingKey) -> Self {
        Self::Ps384(key)
    }
}

impl From<super::Ps512VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Ps512VerifyingKey) -> Self {
        Self::Ps512(key)
    }
}

impl From<super::Es256VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es256VerifyingKey) -> Self {
        Self::Es256(key)
    }
}

impl From<super::Es384VerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es384VerifyingKey) -> Self {
        Self::Es384(key)
    }
}

impl From<super::Es256KVerifyingKey> for AsymmetricVerifyingKey {
    fn from(key: super::Es256KVerifyingKey) -> Self {
        Self::Es256K(key)
    }
}

impl signature::Verifier<Signature> for AsymmetricVerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), ecdsa::Error> {
        match self {
            Self::Rs256(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Rs384(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Rs512(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Ps256(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Ps384(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Ps512(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es256(key) => {
                let signature: ecdsa::Signature<_> = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es384(key) => {
                let signature: ecdsa::Signature<_> = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Es256K(key) => {
                let signature: ecdsa::Signature<_> = signature.to_signature()?;
                key.verify(msg, &signature)
            }
        }
    }
}
