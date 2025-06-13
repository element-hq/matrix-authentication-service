// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashMap;

use assert_matches::assert_matches;
use chrono::{DateTime, Duration, Utc};
use mas_iana::jose::JsonWebSignatureAlg;
use mas_jose::{
    claims::{self, ClaimError},
    constraints::Constrainable,
    jwk::PublicJsonWebKeySet,
    jwt::{JsonWebSignatureHeader, Jwt},
};
use mas_oidc_client::{
    error::{IdTokenError, JwtVerificationError},
    requests::jose::{JwtVerificationData, verify_id_token},
    types::IdToken,
};

use crate::{CLIENT_ID, ID_TOKEN_SIGNING_ALG, SUBJECT_IDENTIFIER, keystore, now};

#[derive(Clone, Copy, PartialEq, Eq)]
enum IdTokenFlag {
    WrongExpiration,
    WrongSubject,
}

/// Generate an ID token with the given settings.
fn id_token(
    issuer: &str,
    flag: Option<IdTokenFlag>,
    auth_time: Option<DateTime<Utc>>,
) -> (IdToken, PublicJsonWebKeySet) {
    let signing_alg = ID_TOKEN_SIGNING_ALG;

    let keystore = keystore(&signing_alg);
    let mut claims = HashMap::new();
    let now = now();

    claims::ISS.insert(&mut claims, issuer.to_owned()).unwrap();
    claims::AUD
        .insert(&mut claims, CLIENT_ID.to_owned())
        .unwrap();

    if flag == Some(IdTokenFlag::WrongSubject) {
        claims::SUB
            .insert(&mut claims, "wrong_subject".to_owned())
            .unwrap();
    } else {
        claims::SUB
            .insert(&mut claims, SUBJECT_IDENTIFIER.to_owned())
            .unwrap();
    }

    claims::IAT.insert(&mut claims, now).unwrap();

    if flag == Some(IdTokenFlag::WrongExpiration) {
        claims::EXP
            .insert(&mut claims, now - Duration::try_hours(1).unwrap())
            .unwrap();
    } else {
        claims::EXP
            .insert(&mut claims, now + Duration::try_hours(1).unwrap())
            .unwrap();
    }

    if let Some(auth_time) = auth_time {
        claims::AUTH_TIME.insert(&mut claims, auth_time).unwrap();
    }

    let key = keystore.signing_key_for_algorithm(&signing_alg).unwrap();
    let signer = key.params().signing_key_for_alg(&signing_alg).unwrap();
    let header = JsonWebSignatureHeader::new(signing_alg).with_kid(key.kid().unwrap());
    let id_token = Jwt::sign(header, claims, &signer).unwrap();

    (id_token, keystore.public_jwks())
}

#[tokio::test]
async fn pass_verify_id_token() {
    let issuer = "http://localhost/";
    let now = now();
    let (auth_id_token, _) = id_token(issuer, None, Some(now));
    let (id_token, jwks) = id_token(issuer, None, Some(now));

    let verification_data = JwtVerificationData {
        issuer: Some(issuer),
        jwks: &jwks,
        client_id: &CLIENT_ID.to_owned(),
        signing_algorithm: &ID_TOKEN_SIGNING_ALG,
    };

    verify_id_token(
        id_token.as_str(),
        verification_data,
        Some(&auth_id_token),
        now,
    )
    .unwrap();
}

#[tokio::test]
async fn fail_verify_id_token_wrong_issuer() {
    let issuer = "http://localhost/";
    let wrong_issuer = "http://distanthost/";
    let (id_token, jwks) = id_token(issuer, None, None);
    let now = now();

    let verification_data = JwtVerificationData {
        issuer: Some(wrong_issuer),
        jwks: &jwks,
        client_id: &CLIENT_ID.to_owned(),
        signing_algorithm: &ID_TOKEN_SIGNING_ALG,
    };

    let error = verify_id_token(id_token.as_str(), verification_data, None, now).unwrap_err();

    assert_matches!(
        error,
        IdTokenError::Jwt(JwtVerificationError::Claim(ClaimError::ValidationError {
            claim: "iss",
            ..
        }))
    );
}

#[tokio::test]
async fn fail_verify_id_token_wrong_audience() {
    let issuer = "http://localhost/";
    let (id_token, jwks) = id_token(issuer, None, None);
    let now = now();

    let verification_data = JwtVerificationData {
        issuer: Some(issuer),
        jwks: &jwks,
        client_id: &"wrong_client_id".to_owned(),
        signing_algorithm: &ID_TOKEN_SIGNING_ALG,
    };

    let error = verify_id_token(id_token.as_str(), verification_data, None, now).unwrap_err();

    assert_matches!(
        error,
        IdTokenError::Jwt(JwtVerificationError::Claim(ClaimError::ValidationError {
            claim: "aud",
            ..
        }))
    );
}

#[tokio::test]
async fn fail_verify_id_token_wrong_signing_algorithm() {
    let issuer = "http://localhost/";
    let (id_token, jwks) = id_token(issuer, None, None);
    let now = now();

    let verification_data = JwtVerificationData {
        issuer: Some(issuer),
        jwks: &jwks,
        client_id: &CLIENT_ID.to_owned(),
        signing_algorithm: &JsonWebSignatureAlg::Unknown("wrong_algorithm".to_owned()),
    };

    let error = verify_id_token(id_token.as_str(), verification_data, None, now).unwrap_err();

    assert_matches!(
        error,
        IdTokenError::Jwt(JwtVerificationError::WrongSignatureAlg)
    );
}

#[tokio::test]
async fn fail_verify_id_token_wrong_expiration() {
    let issuer = "http://localhost/";
    let (id_token, jwks) = id_token(issuer, Some(IdTokenFlag::WrongExpiration), None);
    let now = now();

    let verification_data = JwtVerificationData {
        issuer: Some(issuer),
        jwks: &jwks,
        client_id: &CLIENT_ID.to_owned(),
        signing_algorithm: &ID_TOKEN_SIGNING_ALG,
    };

    let error = verify_id_token(id_token.as_str(), verification_data, None, now).unwrap_err();

    assert_matches!(error, IdTokenError::Claim(_));
}

#[tokio::test]
async fn fail_verify_id_token_wrong_subject() {
    let issuer = "http://localhost/";
    let now = now();
    let (auth_id_token, _) = id_token(issuer, None, Some(now));
    let (id_token, jwks) = id_token(issuer, Some(IdTokenFlag::WrongSubject), None);

    let verification_data = JwtVerificationData {
        issuer: Some(issuer),
        jwks: &jwks,
        client_id: &CLIENT_ID.to_owned(),
        signing_algorithm: &ID_TOKEN_SIGNING_ALG,
    };

    let error = verify_id_token(
        id_token.as_str(),
        verification_data,
        Some(&auth_id_token),
        now,
    )
    .unwrap_err();

    assert_matches!(error, IdTokenError::WrongSubjectIdentifier);
}

#[tokio::test]
async fn fail_verify_id_token_wrong_auth_time() {
    let issuer = "http://localhost/";
    let now = now();
    let (auth_id_token, _) = id_token(issuer, None, Some(now));
    let (id_token, jwks) = id_token(issuer, None, Some(now + Duration::try_hours(1).unwrap()));

    let verification_data = JwtVerificationData {
        issuer: Some(issuer),
        jwks: &jwks,
        client_id: &CLIENT_ID.to_owned(),
        signing_algorithm: &ID_TOKEN_SIGNING_ALG,
    };

    let error = verify_id_token(
        id_token.as_str(),
        verification_data,
        Some(&auth_id_token),
        now,
    )
    .unwrap_err();

    assert_matches!(error, IdTokenError::WrongAuthTime);
}
