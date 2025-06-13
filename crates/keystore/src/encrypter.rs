// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use aead::Aead;
use base64ct::{Base64, Encoding};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use generic_array::GenericArray;
use thiserror::Error;

/// Helps encrypting and decrypting data
#[derive(Clone)]
pub struct Encrypter {
    aead: Arc<ChaCha20Poly1305>,
}

#[derive(Debug, Error)]
#[error("Decryption error")]
pub enum DecryptError {
    Aead(#[from] aead::Error),
    Base64(#[from] base64ct::Error),
    Shape,
}

impl Encrypter {
    /// Creates an [`Encrypter`] out of an encryption key
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let key = GenericArray::from_slice(key);
        let aead = ChaCha20Poly1305::new(key);
        let aead = Arc::new(aead);
        Self { aead }
    }

    /// Encrypt a payload
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to encrypt
    pub fn encrypt(&self, nonce: &[u8; 12], decrypted: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let nonce = GenericArray::from_slice(&nonce[..]);
        let encrypted = self.aead.encrypt(nonce, decrypted)?;
        Ok(encrypted)
    }

    /// Decrypts a payload
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to decrypt
    pub fn decrypt(&self, nonce: &[u8; 12], encrypted: &[u8]) -> Result<Vec<u8>, aead::Error> {
        let nonce = GenericArray::from_slice(&nonce[..]);
        let encrypted = self.aead.decrypt(nonce, encrypted)?;
        Ok(encrypted)
    }

    /// Encrypt a payload to a self-contained base64-encoded string
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to encrypt
    pub fn encrypt_to_string(&self, decrypted: &[u8]) -> Result<String, aead::Error> {
        let nonce = rand::random();
        let encrypted = self.encrypt(&nonce, decrypted)?;
        let encrypted = [&nonce[..], &encrypted].concat();
        let encrypted = Base64::encode_string(&encrypted);
        Ok(encrypted)
    }

    /// Decrypt a payload from a self-contained base64-encoded string
    ///
    /// # Errors
    ///
    /// Will return `Err` when the payload failed to decrypt
    pub fn decrypt_string(&self, encrypted: &str) -> Result<Vec<u8>, DecryptError> {
        let encrypted = Base64::decode_vec(encrypted)?;

        let nonce: &[u8; 12] = encrypted
            .get(0..12)
            .ok_or(DecryptError::Shape)?
            .try_into()
            .map_err(|_| DecryptError::Shape)?;

        let payload = encrypted.get(12..).ok_or(DecryptError::Shape)?;

        let decrypted_client_secret = self.decrypt(nonce, payload)?;

        Ok(decrypted_client_secret)
    }
}
