// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use mas_iana::jose::JsonWebSignatureAlg;
use sha2::{Sha256, Sha384, Sha512};

mod asymmetric;
pub(crate) mod hmac;
mod signature;
mod symmetric;

pub use self::{
    asymmetric::{AsymmetricKeyFromJwkError, AsymmetricSigningKey, AsymmetricVerifyingKey},
    symmetric::{InvalidAlgorithm, SymmetricKey},
};

pub type Hs256Key = self::hmac::Hmac<Sha256>;
pub type Hs384Key = self::hmac::Hmac<Sha384>;
pub type Hs512Key = self::hmac::Hmac<Sha512>;

pub type Rs256SigningKey = rsa::pkcs1v15::SigningKey<Sha256>;
pub type Rs256VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha256>;
pub type Rs384SigningKey = rsa::pkcs1v15::SigningKey<Sha384>;
pub type Rs384VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha384>;
pub type Rs512SigningKey = rsa::pkcs1v15::SigningKey<Sha512>;
pub type Rs512VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha512>;

pub type Ps256SigningKey = rsa::pss::SigningKey<Sha256>;
pub type Ps256VerifyingKey = rsa::pss::VerifyingKey<Sha256>;
pub type Ps384SigningKey = rsa::pss::SigningKey<Sha384>;
pub type Ps384VerifyingKey = rsa::pss::VerifyingKey<Sha384>;
pub type Ps512SigningKey = rsa::pss::SigningKey<Sha512>;
pub type Ps512VerifyingKey = rsa::pss::VerifyingKey<Sha512>;

pub type Es256SigningKey = ecdsa::SigningKey<p256::NistP256>;
pub type Es256VerifyingKey = ecdsa::VerifyingKey<p256::NistP256>;
pub type Es384SigningKey = ecdsa::SigningKey<p384::NistP384>;
pub type Es384VerifyingKey = ecdsa::VerifyingKey<p384::NistP384>;
pub type Es256KSigningKey = ecdsa::SigningKey<k256::Secp256k1>;
pub type Es256KVerifyingKey = ecdsa::VerifyingKey<k256::Secp256k1>;

/// All the signing algorithms supported by this crate.
pub const SUPPORTED_SIGNING_ALGORITHMS: [JsonWebSignatureAlg; 12] = [
    JsonWebSignatureAlg::Hs256,
    JsonWebSignatureAlg::Hs384,
    JsonWebSignatureAlg::Hs512,
    JsonWebSignatureAlg::Rs256,
    JsonWebSignatureAlg::Rs384,
    JsonWebSignatureAlg::Rs512,
    JsonWebSignatureAlg::Ps256,
    JsonWebSignatureAlg::Ps384,
    JsonWebSignatureAlg::Ps512,
    JsonWebSignatureAlg::Es256,
    JsonWebSignatureAlg::Es384,
    JsonWebSignatureAlg::Es256K,
];
