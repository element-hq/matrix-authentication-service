// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::marker::PhantomData;

use digest::{
    Digest, Mac, OutputSizeUser,
    crypto_common::BlockSizeUser,
    generic_array::{ArrayLength, GenericArray},
};
use signature::{Signer, Verifier};
use thiserror::Error;

pub struct Signature<S: ArrayLength<u8>> {
    signature: GenericArray<u8, S>,
}

impl<S: ArrayLength<u8>> PartialEq for Signature<S> {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature
    }
}

impl<S: ArrayLength<u8>> Eq for Signature<S> {}

impl<S: ArrayLength<u8>> std::fmt::Debug for Signature<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.signature)
    }
}

impl<S: ArrayLength<u8>> Clone for Signature<S> {
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
        }
    }
}

impl<S: ArrayLength<u8>> From<Signature<S>> for GenericArray<u8, S> {
    fn from(val: Signature<S>) -> Self {
        val.signature
    }
}

impl<'a, S: ArrayLength<u8>> TryFrom<&'a [u8]> for Signature<S> {
    type Error = InvalidLength;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != S::to_usize() {
            return Err(InvalidLength);
        }
        let mut signature = GenericArray::default();
        signature.copy_from_slice(value);
        Ok(Self { signature })
    }
}

impl<S: ArrayLength<u8>> signature::SignatureEncoding for Signature<S> {
    type Repr = GenericArray<u8, S>;
}

impl<S: ArrayLength<u8>> AsRef<[u8]> for Signature<S> {
    fn as_ref(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

pub struct Hmac<D> {
    key: Vec<u8>,
    digest: PhantomData<D>,
}

impl<D> Hmac<D> {
    pub const fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            digest: PhantomData,
        }
    }
}

#[derive(Error, Debug)]
#[error("invalid length")]
pub struct InvalidLength;

impl<D> From<Vec<u8>> for Hmac<D> {
    fn from(key: Vec<u8>) -> Self {
        Self {
            key,
            digest: PhantomData,
        }
    }
}

impl<D: Digest + BlockSizeUser>
    Signer<Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>> for Hmac<D>
{
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> Result<Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>, signature::Error>
    {
        let mut mac = <hmac::SimpleHmac<D> as Mac>::new_from_slice(&self.key)
            .map_err(signature::Error::from_source)?;
        mac.update(msg);
        let signature = mac.finalize().into_bytes();
        Ok(Signature { signature })
    }
}

impl<D: Digest + BlockSizeUser>
    Verifier<Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>> for Hmac<D>
{
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>,
    ) -> Result<(), signature::Error> {
        let new_signature = self.try_sign(msg)?;
        if &new_signature != signature {
            return Err(signature::Error::new());
        }
        Ok(())
    }
}
