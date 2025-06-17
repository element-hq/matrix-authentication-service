// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use signature::SignatureEncoding as _;

#[derive(Debug, Clone)]
pub struct Signature {
    bytes: Box<[u8]>,
}

impl From<Signature> for Box<[u8]> {
    fn from(val: Signature) -> Self {
        val.bytes
    }
}

impl<'a> From<&'a [u8]> for Signature {
    fn from(value: &'a [u8]) -> Self {
        Self {
            bytes: value.into(),
        }
    }
}

impl signature::SignatureEncoding for Signature {
    type Repr = Box<[u8]>;
}

impl Signature {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    pub fn from_signature<S>(signature: &S) -> Self
    where
        S: signature::SignatureEncoding,
    {
        Self {
            bytes: signature.to_vec().into(),
        }
    }

    pub fn to_signature<S>(&self) -> Result<S, signature::Error>
    where
        S: signature::SignatureEncoding,
    {
        S::try_from(&self.to_bytes()).map_err(|_| signature::Error::default())
    }
}
