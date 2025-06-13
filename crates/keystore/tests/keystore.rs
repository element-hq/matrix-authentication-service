// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use der::pem::LineEnding;
use mas_iana::jose::JsonWebSignatureAlg;
use mas_jose::{
    jwk::ParametersInfo,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use mas_keystore::{JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
use rand::SeedableRng;

static PASSWORD: &str = "hunter2";

/// Generate a test which loads a key, and then tries signing and verifying a
/// JWT for each available algorithm
macro_rules! plain_test {
    ($name:ident, $kind:ident, $path:literal) => {
        #[test]
        fn $name() {
            let bytes = include_bytes!(concat!("./keys/", $path));
            let key = PrivateKey::load(bytes).unwrap();
            assert!(matches!(key, PrivateKey::$kind(_)), "wrong key type");

            let algs = key.possible_algs();
            assert_ne!(algs.len(), 0);

            for alg in algs {
                let header = JsonWebSignatureHeader::new(alg.clone());
                let payload = "hello";
                let signer = key.signing_key_for_alg(alg).unwrap();
                let jwt = Jwt::sign(header, payload, &signer).unwrap();
                let verifier = key.verifying_key_for_alg(alg).unwrap();
                jwt.verify(&verifier).unwrap();
            }
        }
    };
}

/// Generate a test which loads an encrypted key, and then tries signing and
/// verifying a JWT for each available algorithm
macro_rules! enc_test {
    ($name:ident, $kind:ident, $path:literal) => {
        #[test]
        fn $name() {
            let bytes = include_bytes!(concat!("./keys/", $path));
            let key = PrivateKey::load_encrypted(bytes, PASSWORD).unwrap();
            assert!(matches!(key, PrivateKey::$kind(_)), "wrong key type");

            let algs = key.possible_algs();
            assert_ne!(algs.len(), 0);

            for alg in algs {
                let header = JsonWebSignatureHeader::new(alg.clone());
                let payload = "hello";
                let signer = key.signing_key_for_alg(alg).unwrap();
                let jwt = Jwt::sign(header, payload, &signer).unwrap();
                let verifier = key.verifying_key_for_alg(alg).unwrap();
                jwt.verify(&verifier).unwrap();
            }
        }
    };
}

/// Generate a PEM decoding and encoding test
macro_rules! pem_test {
    ($name:ident, $path:literal) => {
        #[test]
        fn $name() {
            let pem = include_str!(concat!("./keys/", $path, ".pem"));
            let key = PrivateKey::load_pem(pem).unwrap();
            let pem2 = key.to_pem(pem_rfc7468::LineEnding::LF).unwrap();

            assert_eq!(pem, pem2.as_str());
        }
    };
}

/// Generate a DER decoding and encoding test
macro_rules! der_test {
    ($name:ident, $path:literal) => {
        #[test]
        fn $name() {
            let der = include_bytes!(concat!("./keys/", $path, ".der"));
            let key = PrivateKey::load_der(der).unwrap();
            let der2 = key.to_der().unwrap();

            assert_eq!(der, der2.as_slice());
        }
    };
}

plain_test!(plain_rsa_pkcs1_pem, Rsa, "rsa.pkcs1.pem");
plain_test!(plain_rsa_pkcs1_der, Rsa, "rsa.pkcs1.der");
plain_test!(plain_rsa_pkcs8_pem, Rsa, "rsa.pkcs8.pem");
plain_test!(plain_rsa_pkcs8_der, Rsa, "rsa.pkcs8.der");
plain_test!(plain_ec_p256_sec1_pem, EcP256, "ec-p256.sec1.pem");
plain_test!(plain_ec_p256_sec1_der, EcP256, "ec-p256.sec1.der");
plain_test!(plain_ec_p256_pkcs8_pem, EcP256, "ec-p256.pkcs8.pem");
plain_test!(plain_ec_p256_pkcs8_der, EcP256, "ec-p256.pkcs8.der");
plain_test!(plain_ec_p384_sec1_pem, EcP384, "ec-p384.sec1.pem");
plain_test!(plain_ec_p384_sec1_der, EcP384, "ec-p384.sec1.der");
plain_test!(plain_ec_p384_pkcs8_pem, EcP384, "ec-p384.pkcs8.pem");
plain_test!(plain_ec_p384_pkcs8_der, EcP384, "ec-p384.pkcs8.der");
plain_test!(plain_ec_k256_sec1_pem, EcK256, "ec-k256.sec1.pem");
plain_test!(plain_ec_k256_sec1_der, EcK256, "ec-k256.sec1.der");
plain_test!(plain_ec_k256_pkcs8_pem, EcK256, "ec-k256.pkcs8.pem");
plain_test!(plain_ec_k256_pkcs8_der, EcK256, "ec-k256.pkcs8.der");

enc_test!(enc_rsa_pkcs8_pem, Rsa, "rsa.pkcs8.encrypted.pem");
enc_test!(enc_rsa_pkcs8_der, Rsa, "rsa.pkcs8.encrypted.der");
enc_test!(enc_ec_p256_pkcs8_pem, EcP256, "ec-p256.pkcs8.encrypted.pem");
enc_test!(enc_ec_p256_pkcs8_der, EcP256, "ec-p256.pkcs8.encrypted.der");
enc_test!(enc_ec_p384_pkcs8_pem, EcP384, "ec-p384.pkcs8.encrypted.pem");
enc_test!(enc_ec_p384_pkcs8_der, EcP384, "ec-p384.pkcs8.encrypted.der");
enc_test!(enc_ec_k256_pkcs8_pem, EcK256, "ec-k256.pkcs8.encrypted.pem");
enc_test!(enc_ec_k256_pkcs8_der, EcK256, "ec-k256.pkcs8.encrypted.der");

// Test PEM/DER serialization
pem_test!(serialize_rsa_pkcs1_pem, "rsa.pkcs1");
der_test!(serialize_rsa_pkcs1_der, "rsa.pkcs1");
pem_test!(serialize_ec_p256_sec1_pem, "ec-p256.sec1");
der_test!(serialize_ec_p256_sec1_der, "ec-p256.sec1");
pem_test!(serialize_ec_p384_sec1_pem, "ec-p384.sec1");
der_test!(serialize_ec_p384_sec1_der, "ec-p384.sec1");
pem_test!(serialize_ec_k256_sec1_pem, "ec-k256.sec1");
der_test!(serialize_ec_k256_sec1_der, "ec-k256.sec1");

#[test]
fn load_encrypted_as_unencrypted_error() {
    let pem = include_str!("./keys/rsa.pkcs8.encrypted.pem");
    assert!(PrivateKey::load_pem(pem).unwrap_err().is_encrypted());

    let der = include_bytes!("./keys/rsa.pkcs8.encrypted.der");
    assert!(PrivateKey::load_der(der).unwrap_err().is_encrypted());
}

#[test]
fn load_unencrypted_as_encrypted_error() {
    let pem = include_str!("./keys/rsa.pkcs8.pem");
    assert!(
        PrivateKey::load_encrypted_pem(pem, PASSWORD)
            .unwrap_err()
            .is_unencrypted()
    );

    let der = include_bytes!("./keys/rsa.pkcs8.der");
    assert!(
        PrivateKey::load_encrypted_der(der, PASSWORD)
            .unwrap_err()
            .is_unencrypted()
    );
}

#[allow(clippy::similar_names)]
#[test]
fn generate_sign_and_verify() {
    // Use a seeded RNG to keep the snapshot stable
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let rsa = PrivateKey::generate_rsa(&mut rng).expect("Failed to generate RSA key");
    insta::assert_snapshot!(&*rsa.to_pem(LineEnding::LF).unwrap());

    let ec_p256 = PrivateKey::generate_ec_p256(&mut rng);
    insta::assert_snapshot!(&*ec_p256.to_pem(LineEnding::LF).unwrap());

    let ec_p384 = PrivateKey::generate_ec_p384(&mut rng);
    insta::assert_snapshot!(&*ec_p384.to_pem(LineEnding::LF).unwrap());

    let ec_k256 = PrivateKey::generate_ec_k256(&mut rng);
    insta::assert_snapshot!(&*ec_k256.to_pem(LineEnding::LF).unwrap());

    // Create a keystore out of the keys
    let keyset = Keystore::new(JsonWebKeySet::new(vec![
        JsonWebKey::new(rsa),
        JsonWebKey::new(ec_p256),
        JsonWebKey::new(ec_p384),
        JsonWebKey::new(ec_k256),
    ]));

    // And extract the public JWKS
    let jwks = keyset.public_jwks();
    insta::assert_yaml_snapshot!(jwks);

    // Try signing for each supported algorithm
    for alg in [
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Ps256,
        JsonWebSignatureAlg::Ps384,
        JsonWebSignatureAlg::Ps512,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256K,
    ] {
        // Find a matching key and sign with it
        let key = keyset.signing_key_for_algorithm(&alg).unwrap();
        let signer = key.params().signing_key_for_alg(&alg).unwrap();
        let header = JsonWebSignatureHeader::new(alg.clone());
        let token = Jwt::sign_with_rng(&mut rng, header, "", &signer).unwrap();
        insta::assert_snapshot!(format!("jwt_{alg}"), token.as_str());

        // Then try to verify from the public JWKS
        token.verify_with_jwks(&jwks).unwrap();
    }
}
