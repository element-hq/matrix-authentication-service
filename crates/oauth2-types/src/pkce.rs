// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Types for the [Proof Key for Code Exchange].
//!
//! [Proof Key for Code Exchange]: https://www.rfc-editor.org/rfc/rfc7636

use std::borrow::Cow;

use base64ct::{Base64UrlUnpadded, Encoding};
use mas_iana::oauth::PkceCodeChallengeMethod;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors that can occur when verifying a code challenge.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodeChallengeError {
    /// The code verifier should be at least 43 characters long.
    #[error("code_verifier should be at least 43 characters long")]
    TooShort,

    /// The code verifier should be at most 128 characters long.
    #[error("code_verifier should be at most 128 characters long")]
    TooLong,

    /// The code verifier contains invalid characters.
    #[error("code_verifier contains invalid characters")]
    InvalidCharacters,

    /// The challenge verification failed.
    #[error("challenge verification failed")]
    VerificationFailed,

    /// The challenge method is unsupported.
    #[error("unknown challenge method")]
    UnknownChallengeMethod,
}

fn validate_verifier(verifier: &str) -> Result<(), CodeChallengeError> {
    if verifier.len() < 43 {
        return Err(CodeChallengeError::TooShort);
    }

    if verifier.len() > 128 {
        return Err(CodeChallengeError::TooLong);
    }

    if !verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
    {
        return Err(CodeChallengeError::InvalidCharacters);
    }

    Ok(())
}

/// Helper trait to compute and verify code challenges.
pub trait CodeChallengeMethodExt {
    /// Compute the challenge for a given verifier
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier did not adhere to the rules defined by
    /// the RFC in terms of length and allowed characters
    fn compute_challenge<'a>(&self, verifier: &'a str) -> Result<Cow<'a, str>, CodeChallengeError>;

    /// Verify that a given verifier is valid for the given challenge
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier did not match the challenge, or if the
    /// verifier did not adhere to the rules defined by the RFC in terms of
    /// length and allowed characters
    fn verify(&self, challenge: &str, verifier: &str) -> Result<(), CodeChallengeError>
    where
        Self: Sized,
    {
        if self.compute_challenge(verifier)? == challenge {
            Ok(())
        } else {
            Err(CodeChallengeError::VerificationFailed)
        }
    }
}

impl CodeChallengeMethodExt for PkceCodeChallengeMethod {
    fn compute_challenge<'a>(&self, verifier: &'a str) -> Result<Cow<'a, str>, CodeChallengeError> {
        validate_verifier(verifier)?;

        let challenge = match self {
            Self::Plain => verifier.into(),
            Self::S256 => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let hash = hasher.finalize();
                let verifier = Base64UrlUnpadded::encode_string(&hash);
                verifier.into()
            }
            _ => return Err(CodeChallengeError::UnknownChallengeMethod),
        };

        Ok(challenge)
    }
}

/// The code challenge data added to an authorization request.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The code challenge method.
    pub code_challenge_method: PkceCodeChallengeMethod,

    /// The code challenge computed from the verifier and the method.
    pub code_challenge: String,
}

/// The code challenge data added to a token request.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// The code challenge verifier.
    pub code_challenge_verifier: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_verification() {
        use PkceCodeChallengeMethod::{Plain, S256};
        // This challenge comes from the RFC7636 appendices
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(
            S256.verify(challenge, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                .is_ok()
        );

        assert!(Plain.verify(challenge, challenge).is_ok());

        assert_eq!(
            S256.verify(challenge, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            Err(CodeChallengeError::VerificationFailed),
        );

        assert_eq!(
            S256.verify(challenge, "tooshort"),
            Err(CodeChallengeError::TooShort),
        );

        assert_eq!(
            S256.verify(challenge, "toolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolong"),
            Err(CodeChallengeError::TooLong),
        );

        assert_eq!(
            S256.verify(
                challenge,
                "this is long enough but has invalid characters in it"
            ),
            Err(CodeChallengeError::InvalidCharacters),
        );
    }
}
