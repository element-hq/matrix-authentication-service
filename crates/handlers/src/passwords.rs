// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use futures_util::future::OptionFuture;
use pbkdf2::Pbkdf2;
use rand::{CryptoRng, RngCore, SeedableRng, distributions::Standard, prelude::Distribution};
use thiserror::Error;
use zeroize::Zeroizing;
use zxcvbn::zxcvbn;

pub type SchemeVersion = u16;

#[derive(Debug, Error)]
#[error("Password manager is disabled")]
pub struct PasswordManagerDisabledError;

#[derive(Clone)]
pub struct PasswordManager {
    inner: Option<Arc<InnerPasswordManager>>,
}

struct InnerPasswordManager {
    /// Minimum complexity score of new passwords (between 0 and 4) as evaluated
    /// by zxcvbn.
    minimum_complexity: u8,
    current_hasher: Hasher,
    current_version: SchemeVersion,

    /// A map of "old" hashers used only for verification
    other_hashers: HashMap<SchemeVersion, Hasher>,
}

impl PasswordManager {
    /// Creates a new [`PasswordManager`] from an iterator and a minimum allowed
    /// complexity score between 0 and 4. The first item in
    /// the iterator will be the default hashing scheme.
    ///
    /// # Errors
    ///
    /// Returns an error if the iterator was empty
    pub fn new<I: IntoIterator<Item = (SchemeVersion, Hasher)>>(
        minimum_complexity: u8,
        iter: I,
    ) -> Result<Self, anyhow::Error> {
        let mut iter = iter.into_iter();

        // Take the first hasher as the current hasher
        let (current_version, current_hasher) = iter
            .next()
            .context("Iterator must have at least one item")?;

        // Collect the other hashers in a map used only in verification
        let other_hashers = iter.collect();

        Ok(Self {
            inner: Some(Arc::new(InnerPasswordManager {
                minimum_complexity,
                current_hasher,
                current_version,
                other_hashers,
            })),
        })
    }

    /// Creates a new disabled password manager
    #[must_use]
    pub const fn disabled() -> Self {
        Self { inner: None }
    }

    /// Checks if the password manager is enabled or not
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Get the inner password manager
    ///
    /// # Errors
    ///
    /// Returns an error if the password manager is disabled
    fn get_inner(&self) -> Result<Arc<InnerPasswordManager>, PasswordManagerDisabledError> {
        self.inner.clone().ok_or(PasswordManagerDisabledError)
    }

    /// Returns true if and only if the given password satisfies the minimum
    /// complexity requirements.
    ///
    /// # Errors
    ///
    /// Returns an error if the password manager is disabled
    pub fn is_password_complex_enough(
        &self,
        password: &str,
    ) -> Result<bool, PasswordManagerDisabledError> {
        let inner = self.get_inner()?;
        let score = zxcvbn(password, &[]);
        Ok(u8::from(score.score()) >= inner.minimum_complexity)
    }

    /// Hash a password with the default hashing scheme.
    /// Returns the version of the hashing scheme used and the hashed password.
    ///
    /// # Errors
    ///
    /// Returns an error if the hashing failed or if the password manager is
    /// disabled
    #[tracing::instrument(name = "passwords.hash", skip_all)]
    pub async fn hash<R: CryptoRng + RngCore + Send>(
        &self,
        rng: R,
        password: Zeroizing<String>,
    ) -> Result<(SchemeVersion, String), anyhow::Error> {
        let inner = self.get_inner()?;

        // Seed a future-local RNG so the RNG passed in parameters doesn't have to be
        // 'static
        let rng = rand_chacha::ChaChaRng::from_rng(rng)?;
        let span = tracing::Span::current();

        // `inner` is being moved in the blocking task, so we need to copy the version
        // first
        let version = inner.current_version;

        let hashed = tokio::task::spawn_blocking(move || {
            span.in_scope(move || inner.current_hasher.hash_blocking(rng, password))
        })
        .await??;

        Ok((version, hashed))
    }

    /// Verify a password hash for the given hashing scheme.
    ///
    /// # Errors
    ///
    /// Returns an error if the password hash verification failed or if the
    /// password manager is disabled
    #[tracing::instrument(name = "passwords.verify", skip_all, fields(%scheme))]
    pub async fn verify(
        &self,
        scheme: SchemeVersion,
        password: Zeroizing<String>,
        hashed_password: String,
    ) -> Result<(), anyhow::Error> {
        let inner = self.get_inner()?;
        let span = tracing::Span::current();

        tokio::task::spawn_blocking(move || {
            span.in_scope(move || {
                let hasher = if scheme == inner.current_version {
                    &inner.current_hasher
                } else {
                    inner
                        .other_hashers
                        .get(&scheme)
                        .context("Hashing scheme not found")?
                };

                hasher.verify_blocking(&hashed_password, password)
            })
        })
        .await??;

        Ok(())
    }

    /// Verify a password hash for the given hashing scheme, and upgrade it on
    /// the fly, if it was not hashed with the default scheme
    ///
    /// # Errors
    ///
    /// Returns an error if the password hash verification failed or if the
    /// password manager is disabled
    #[tracing::instrument(name = "passwords.verify_and_upgrade", skip_all, fields(%scheme))]
    pub async fn verify_and_upgrade<R: CryptoRng + RngCore + Send>(
        &self,
        rng: R,
        scheme: SchemeVersion,
        password: Zeroizing<String>,
        hashed_password: String,
    ) -> Result<Option<(SchemeVersion, String)>, anyhow::Error> {
        let inner = self.get_inner()?;

        // If the current scheme isn't the default one, we also hash with the default
        // one so that
        let new_hash_fut: OptionFuture<_> = (scheme != inner.current_version)
            .then(|| self.hash(rng, password.clone()))
            .into();

        let verify_fut = self.verify(scheme, password, hashed_password);

        let (new_hash_res, verify_res) = tokio::join!(new_hash_fut, verify_fut);
        verify_res?;

        let new_hash = new_hash_res.transpose()?;

        Ok(new_hash)
    }
}

/// A hashing scheme, with an optional pepper
pub struct Hasher {
    algorithm: Algorithm,
    unicode_normalization: bool,
    pepper: Option<Vec<u8>>,
}

impl Hasher {
    /// Creates a new hashing scheme based on the bcrypt algorithm
    #[must_use]
    pub const fn bcrypt(
        cost: Option<u32>,
        pepper: Option<Vec<u8>>,
        unicode_normalization: bool,
    ) -> Self {
        let algorithm = Algorithm::Bcrypt { cost };
        Self {
            algorithm,
            unicode_normalization,
            pepper,
        }
    }

    /// Creates a new hashing scheme based on the argon2id algorithm
    #[must_use]
    pub const fn argon2id(pepper: Option<Vec<u8>>, unicode_normalization: bool) -> Self {
        let algorithm = Algorithm::Argon2id;
        Self {
            algorithm,
            unicode_normalization,
            pepper,
        }
    }

    /// Creates a new hashing scheme based on the pbkdf2 algorithm
    #[must_use]
    pub const fn pbkdf2(pepper: Option<Vec<u8>>, unicode_normalization: bool) -> Self {
        let algorithm = Algorithm::Pbkdf2;
        Self {
            algorithm,
            unicode_normalization,
            pepper,
        }
    }

    fn normalize_password(&self, password: Zeroizing<String>) -> Zeroizing<String> {
        if self.unicode_normalization {
            // This is the normalization method used by Synapse
            let normalizer = icu_normalizer::ComposingNormalizer::new_nfkc();
            Zeroizing::new(normalizer.normalize(&password))
        } else {
            password
        }
    }

    fn hash_blocking<R: CryptoRng + RngCore>(
        &self,
        rng: R,
        password: Zeroizing<String>,
    ) -> Result<String, anyhow::Error> {
        let password = self.normalize_password(password);

        self.algorithm
            .hash_blocking(rng, password.as_bytes(), self.pepper.as_deref())
    }

    fn verify_blocking(
        &self,
        hashed_password: &str,
        password: Zeroizing<String>,
    ) -> Result<(), anyhow::Error> {
        let password = self.normalize_password(password);

        self.algorithm
            .verify_blocking(hashed_password, password.as_bytes(), self.pepper.as_deref())
    }
}

#[derive(Debug, Clone, Copy)]
enum Algorithm {
    Bcrypt { cost: Option<u32> },
    Argon2id,
    Pbkdf2,
}

impl Algorithm {
    fn hash_blocking<R: CryptoRng + RngCore>(
        self,
        mut rng: R,
        password: &[u8],
        pepper: Option<&[u8]>,
    ) -> Result<String, anyhow::Error> {
        match self {
            Self::Bcrypt { cost } => {
                let mut password = Zeroizing::new(password.to_vec());
                if let Some(pepper) = pepper {
                    password.extend_from_slice(pepper);
                }

                let salt = Standard.sample(&mut rng);

                let hashed = bcrypt::hash_with_salt(password, cost.unwrap_or(12), salt)?;
                Ok(hashed.format_for_version(bcrypt::Version::TwoB))
            }

            Self::Argon2id => {
                let algorithm = argon2::Algorithm::default();
                let version = argon2::Version::default();
                let params = argon2::Params::default();

                let phf = if let Some(secret) = pepper {
                    Argon2::new_with_secret(secret, algorithm, version, params)?
                } else {
                    Argon2::new(algorithm, version, params)
                };

                let salt = SaltString::generate(rng);
                let hashed = phf.hash_password(password.as_ref(), &salt)?;
                Ok(hashed.to_string())
            }

            Self::Pbkdf2 => {
                let mut password = Zeroizing::new(password.to_vec());
                if let Some(pepper) = pepper {
                    password.extend_from_slice(pepper);
                }

                let salt = SaltString::generate(rng);
                let hashed = Pbkdf2.hash_password(password.as_ref(), &salt)?;
                Ok(hashed.to_string())
            }
        }
    }

    fn verify_blocking(
        self,
        hashed_password: &str,
        password: &[u8],
        pepper: Option<&[u8]>,
    ) -> Result<(), anyhow::Error> {
        match self {
            Algorithm::Bcrypt { .. } => {
                let mut password = Zeroizing::new(password.to_vec());
                if let Some(pepper) = pepper {
                    password.extend_from_slice(pepper);
                }

                let result = bcrypt::verify(password, hashed_password)?;
                anyhow::ensure!(result, "wrong password");
            }

            Algorithm::Argon2id => {
                let algorithm = argon2::Algorithm::default();
                let version = argon2::Version::default();
                let params = argon2::Params::default();

                let phf = if let Some(secret) = pepper {
                    Argon2::new_with_secret(secret, algorithm, version, params)?
                } else {
                    Argon2::new(algorithm, version, params)
                };

                let hashed_password = PasswordHash::new(hashed_password)?;

                phf.verify_password(password.as_ref(), &hashed_password)?;
            }

            Algorithm::Pbkdf2 => {
                let mut password = Zeroizing::new(password.to_vec());
                if let Some(pepper) = pepper {
                    password.extend_from_slice(pepper);
                }

                let hashed_password = PasswordHash::new(hashed_password)?;

                Pbkdf2.verify_password(password.as_ref(), &hashed_password)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn hashing_bcrypt() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = b"hunter2";
        let password2 = b"wrong-password";
        let pepper = b"a-secret-pepper";
        let pepper2 = b"the-wrong-pepper";

        let alg = Algorithm::Bcrypt { cost: Some(10) };
        // Hash with a pepper
        let hash = alg
            .hash_blocking(&mut rng, password, Some(pepper))
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert!(alg.verify_blocking(&hash, password, Some(pepper)).is_ok());
        assert!(alg.verify_blocking(&hash, password2, Some(pepper)).is_err());
        assert!(alg.verify_blocking(&hash, password, Some(pepper2)).is_err());
        assert!(alg.verify_blocking(&hash, password, None).is_err());

        // Hash without pepper
        let hash = alg
            .hash_blocking(&mut rng, password, None)
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert!(alg.verify_blocking(&hash, password, None).is_ok());
        assert!(alg.verify_blocking(&hash, password2, None).is_err());
        assert!(alg.verify_blocking(&hash, password, Some(pepper)).is_err());
    }

    #[test]
    fn hashing_argon2id() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = b"hunter2";
        let password2 = b"wrong-password";
        let pepper = b"a-secret-pepper";
        let pepper2 = b"the-wrong-pepper";

        let alg = Algorithm::Argon2id;
        // Hash with a pepper
        let hash = alg
            .hash_blocking(&mut rng, password, Some(pepper))
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert!(alg.verify_blocking(&hash, password, Some(pepper)).is_ok());
        assert!(alg.verify_blocking(&hash, password2, Some(pepper)).is_err());
        assert!(alg.verify_blocking(&hash, password, Some(pepper2)).is_err());
        assert!(alg.verify_blocking(&hash, password, None).is_err());

        // Hash without pepper
        let hash = alg
            .hash_blocking(&mut rng, password, None)
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert!(alg.verify_blocking(&hash, password, None).is_ok());
        assert!(alg.verify_blocking(&hash, password2, None).is_err());
        assert!(alg.verify_blocking(&hash, password, Some(pepper)).is_err());
    }

    #[test]
    #[ignore = "this is particularly slow (20s+ seconds)"]
    fn hashing_pbkdf2() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = b"hunter2";
        let password2 = b"wrong-password";
        let pepper = b"a-secret-pepper";
        let pepper2 = b"the-wrong-pepper";

        let alg = Algorithm::Pbkdf2;
        // Hash with a pepper
        let hash = alg
            .hash_blocking(&mut rng, password, Some(pepper))
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert!(alg.verify_blocking(&hash, password, Some(pepper)).is_ok());
        assert!(alg.verify_blocking(&hash, password2, Some(pepper)).is_err());
        assert!(alg.verify_blocking(&hash, password, Some(pepper2)).is_err());
        assert!(alg.verify_blocking(&hash, password, None).is_err());

        // Hash without pepper
        let hash = alg
            .hash_blocking(&mut rng, password, None)
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert!(alg.verify_blocking(&hash, password, None).is_ok());
        assert!(alg.verify_blocking(&hash, password2, None).is_err());
        assert!(alg.verify_blocking(&hash, password, Some(pepper)).is_err());
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn hash_verify_and_upgrade() {
        // Tests the whole password manager, by hashing a password and upgrading it
        // after changing the hashing schemes. The salt generation is done with a seeded
        // RNG, so that we can do stable snapshots of hashed passwords
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = Zeroizing::new("hunter2".to_owned());
        let wrong_password = Zeroizing::new("wrong-password".to_owned());

        let manager = PasswordManager::new(
            0,
            [
                // Start with one hashing scheme: the one used by synapse, bcrypt + pepper
                (
                    1,
                    Hasher::bcrypt(Some(10), Some(b"a-secret-pepper".to_vec()), false),
                ),
            ],
        )
        .unwrap();

        let (version, hash) = manager
            .hash(&mut rng, password.clone())
            .await
            .expect("Failed to hash");

        assert_eq!(version, 1);
        insta::assert_snapshot!(hash);

        // Just verifying works
        manager
            .verify(version, password.clone(), hash.clone())
            .await
            .expect("Failed to verify");

        // And doesn't work with the wrong password
        manager
            .verify(version, wrong_password.clone(), hash.clone())
            .await
            .expect_err("Verification should have failed");

        // Verifying with the wrong version doesn't work
        manager
            .verify(2, password.clone(), hash.clone())
            .await
            .expect_err("Verification should have failed");

        // Upgrading does nothing
        let res = manager
            .verify_and_upgrade(&mut rng, version, password.clone(), hash.clone())
            .await
            .expect("Failed to verify");

        assert!(res.is_none());

        // Upgrading still verify that the password matches
        manager
            .verify_and_upgrade(&mut rng, version, wrong_password.clone(), hash.clone())
            .await
            .expect_err("Verification should have failed");

        let manager = PasswordManager::new(
            0,
            [
                (2, Hasher::argon2id(None, false)),
                (
                    1,
                    Hasher::bcrypt(Some(10), Some(b"a-secret-pepper".to_vec()), false),
                ),
            ],
        )
        .unwrap();

        // Verifying still works
        manager
            .verify(version, password.clone(), hash.clone())
            .await
            .expect("Failed to verify");

        // And doesn't work with the wrong password
        manager
            .verify(version, wrong_password.clone(), hash.clone())
            .await
            .expect_err("Verification should have failed");

        // Upgrading does re-hash
        let res = manager
            .verify_and_upgrade(&mut rng, version, password.clone(), hash.clone())
            .await
            .expect("Failed to verify");

        assert!(res.is_some());
        let (version, hash) = res.unwrap();

        assert_eq!(version, 2);
        insta::assert_snapshot!(hash);

        // Upgrading works with the new hash, but does not upgrade
        let res = manager
            .verify_and_upgrade(&mut rng, version, password.clone(), hash.clone())
            .await
            .expect("Failed to verify");

        assert!(res.is_none());

        // Upgrading still verify that the password matches
        manager
            .verify_and_upgrade(&mut rng, version, wrong_password.clone(), hash.clone())
            .await
            .expect_err("Verification should have failed");

        // Upgrading still verify that the password matches
        manager
            .verify_and_upgrade(&mut rng, version, wrong_password.clone(), hash.clone())
            .await
            .expect_err("Verification should have failed");

        let manager = PasswordManager::new(
            0,
            [
                (
                    3,
                    Hasher::argon2id(Some(b"a-secret-pepper".to_vec()), false),
                ),
                (2, Hasher::argon2id(None, false)),
                (
                    1,
                    Hasher::bcrypt(Some(10), Some(b"a-secret-pepper".to_vec()), false),
                ),
            ],
        )
        .unwrap();

        // Verifying still works
        manager
            .verify(version, password.clone(), hash.clone())
            .await
            .expect("Failed to verify");

        // And doesn't work with the wrong password
        manager
            .verify(version, wrong_password.clone(), hash.clone())
            .await
            .expect_err("Verification should have failed");

        // Upgrading does re-hash
        let res = manager
            .verify_and_upgrade(&mut rng, version, password.clone(), hash.clone())
            .await
            .expect("Failed to verify");

        assert!(res.is_some());
        let (version, hash) = res.unwrap();

        assert_eq!(version, 3);
        insta::assert_snapshot!(hash);

        // Upgrading works with the new hash, but does not upgrade
        let res = manager
            .verify_and_upgrade(&mut rng, version, password.clone(), hash.clone())
            .await
            .expect("Failed to verify");

        assert!(res.is_none());

        // Upgrading still verify that the password matches
        manager
            .verify_and_upgrade(&mut rng, version, wrong_password.clone(), hash.clone())
            .await
            .expect_err("Verification should have failed");
    }
}
