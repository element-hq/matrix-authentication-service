// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_jose::{
    claims::{self, hash_token},
    constraints::Constrainable,
    jwk::PublicJsonWebKeySet,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use mas_keystore::{JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
use mas_oidc_client::types::{IdToken, client_credentials::ClientCredentials};
use rand::{
    SeedableRng,
    distributions::{Alphanumeric, DistString},
};
use url::Url;
use wiremock::MockServer;

mod requests;
mod types;

const REDIRECT_URI: &str = "http://localhost/";
const CLIENT_ID: &str = "client!+ID";
const CLIENT_SECRET: &str = "SECRET?%Gclient";
const AUTHORIZATION_CODE: &str = "authC0D3";
const CODE_VERIFIER: &str = "cODEv3R1f1ER";
const NONCE: &str = "No0o0o0once";
const ACCESS_TOKEN: &str = "AccessToken1";
const REFRESH_TOKEN: &str = "RefreshToken1";
const SUBJECT_IDENTIFIER: &str = "SubjectID";
const ID_TOKEN_SIGNING_ALG: JsonWebSignatureAlg = JsonWebSignatureAlg::Rs256;

fn now() -> DateTime<Utc> {
    #[allow(clippy::disallowed_methods)]
    Utc::now()
}

async fn init_test() -> (reqwest::Client, MockServer, Url) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let client = mas_http::reqwest_client();
    let mock_server = MockServer::start().await;
    let issuer = Url::parse(&mock_server.uri()).expect("Couldn't parse URL");

    (client, mock_server, issuer)
}

/// Generate a keystore with a single key for the given algorithm.
fn keystore(alg: &JsonWebSignatureAlg) -> Keystore {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    let private_key = match alg {
        JsonWebSignatureAlg::Rs256
        | JsonWebSignatureAlg::Rs384
        | JsonWebSignatureAlg::Rs512
        | JsonWebSignatureAlg::Ps256
        | JsonWebSignatureAlg::Ps384
        | JsonWebSignatureAlg::Ps512 => PrivateKey::generate_rsa(&mut rng).unwrap(),
        JsonWebSignatureAlg::Es256 => PrivateKey::generate_ec_p256(&mut rng),
        JsonWebSignatureAlg::Es384 => PrivateKey::generate_ec_p384(&mut rng),
        _ => unimplemented!(),
    };

    let jwk = JsonWebKey::new(private_key).with_kid(Alphanumeric.sample_string(&mut rng, 10));

    Keystore::new(JsonWebKeySet::new(vec![jwk]))
}

/// Generate an ID token.
fn id_token(issuer: &str) -> (IdToken, PublicJsonWebKeySet) {
    let signing_alg = ID_TOKEN_SIGNING_ALG;

    let keystore = keystore(&signing_alg);
    let mut claims = HashMap::new();
    let now = now();

    claims::ISS.insert(&mut claims, issuer.to_owned()).unwrap();
    claims::SUB
        .insert(&mut claims, SUBJECT_IDENTIFIER.to_owned())
        .unwrap();
    claims::AUD
        .insert(&mut claims, CLIENT_ID.to_owned())
        .unwrap();
    claims::NONCE.insert(&mut claims, NONCE.to_owned()).unwrap();

    claims::IAT.insert(&mut claims, now).unwrap();
    claims::EXP
        .insert(&mut claims, now + Duration::try_hours(1).unwrap())
        .unwrap();

    claims::AT_HASH
        .insert(&mut claims, hash_token(&signing_alg, ACCESS_TOKEN).unwrap())
        .unwrap();
    claims::C_HASH
        .insert(
            &mut claims,
            hash_token(&signing_alg, AUTHORIZATION_CODE).unwrap(),
        )
        .unwrap();

    let key = keystore.signing_key_for_algorithm(&signing_alg).unwrap();
    let signer = key.params().signing_key_for_alg(&signing_alg).unwrap();
    let header = JsonWebSignatureHeader::new(signing_alg).with_kid(key.kid().unwrap());
    let id_token = Jwt::sign(header, claims, &signer).unwrap();

    (id_token, keystore.public_jwks())
}

/// Generate client credentials for the given authentication method.
fn client_credentials(
    auth_method: &OAuthClientAuthenticationMethod,
    issuer: &Url,
) -> ClientCredentials {
    match auth_method {
        OAuthClientAuthenticationMethod::None => ClientCredentials::None {
            client_id: CLIENT_ID.to_owned(),
        },
        OAuthClientAuthenticationMethod::ClientSecretPost => ClientCredentials::ClientSecretPost {
            client_id: CLIENT_ID.to_owned(),
            client_secret: CLIENT_SECRET.to_owned(),
        },
        OAuthClientAuthenticationMethod::ClientSecretBasic => {
            ClientCredentials::ClientSecretBasic {
                client_id: CLIENT_ID.to_owned(),
                client_secret: CLIENT_SECRET.to_owned(),
            }
        }
        OAuthClientAuthenticationMethod::ClientSecretJwt => ClientCredentials::ClientSecretJwt {
            client_id: CLIENT_ID.to_owned(),
            client_secret: CLIENT_SECRET.to_owned(),
            signing_algorithm: JsonWebSignatureAlg::Hs256,
            token_endpoint: issuer.join("token").unwrap(),
        },
        OAuthClientAuthenticationMethod::PrivateKeyJwt => {
            let signing_algorithm = JsonWebSignatureAlg::Es256;

            ClientCredentials::PrivateKeyJwt {
                client_id: CLIENT_ID.to_owned(),
                keystore: keystore(&signing_algorithm),
                signing_algorithm,
                token_endpoint: issuer.join("token").unwrap(),
            }
        }
        _ => unimplemented!(),
    }
}
