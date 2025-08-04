// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use mas_iana::jose::JsonWebSignatureAlg;
use thiserror::Error;

use super::signature::Signature;

// An enum of all supported symmetric signing algorithms keys
#[non_exhaustive]
pub enum SymmetricKey {
    Hs256(super::Hs256Key),
    Hs384(super::Hs384Key),
    Hs512(super::Hs512Key),
}

#[derive(Debug, Error)]
#[error("Invalid algorithm {alg} used for symetric key")]
pub struct InvalidAlgorithm {
    pub alg: JsonWebSignatureAlg,
    pub key: Vec<u8>,
}

impl SymmetricKey {
    /// Create a new symmetric key for the given algorithm with the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the algorithm is not supported.
    pub fn new_for_alg(key: Vec<u8>, alg: &JsonWebSignatureAlg) -> Result<Self, InvalidAlgorithm> {
        match alg {
            JsonWebSignatureAlg::Hs256 => Ok(Self::hs256(key)),
            JsonWebSignatureAlg::Hs384 => Ok(Self::hs384(key)),
            JsonWebSignatureAlg::Hs512 => Ok(Self::hs512(key)),
            _ => Err(InvalidAlgorithm {
                alg: alg.clone(),
                key,
            }),
        }
    }

    /// Create a new symmetric key using the HS256 algorithm with the given key.
    #[must_use]
    pub const fn hs256(key: Vec<u8>) -> Self {
        Self::Hs256(super::Hs256Key::new(key))
    }

    /// Create a new symmetric key using the HS384 algorithm with the given key.
    #[must_use]
    pub const fn hs384(key: Vec<u8>) -> Self {
        Self::Hs384(super::Hs384Key::new(key))
    }

    /// Create a new symmetric key using the HS512 algorithm with the given key.
    #[must_use]
    pub const fn hs512(key: Vec<u8>) -> Self {
        Self::Hs512(super::Hs512Key::new(key))
    }
}

impl From<super::Hs256Key> for SymmetricKey {
    fn from(key: super::Hs256Key) -> Self {
        Self::Hs256(key)
    }
}

impl From<super::Hs384Key> for SymmetricKey {
    fn from(key: super::Hs384Key) -> Self {
        Self::Hs384(key)
    }
}

impl From<super::Hs512Key> for SymmetricKey {
    fn from(key: super::Hs512Key) -> Self {
        Self::Hs512(key)
    }
}

impl signature::RandomizedSigner<Signature> for SymmetricKey {
    fn try_sign_with_rng(
        &self,
        _rng: &mut (impl rand::CryptoRng + rand::RngCore),
        msg: &[u8],
    ) -> Result<Signature, signature::Error> {
        // XXX: is that implementation alright?
        signature::Signer::try_sign(self, msg)
    }
}

impl signature::Signer<Signature> for SymmetricKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        match self {
            Self::Hs256(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Hs384(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
            Self::Hs512(key) => {
                let signature = key.try_sign(msg)?;
                Ok(Signature::from_signature(&signature))
            }
        }
    }
}

impl signature::Verifier<Signature> for SymmetricKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        match self {
            Self::Hs256(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Hs384(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
            Self::Hs512(key) => {
                let signature = signature.to_signature()?;
                key.verify(msg, &signature)
            }
        }
    }
}
