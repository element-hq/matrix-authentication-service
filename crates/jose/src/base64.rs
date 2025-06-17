// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Transparent base64 encoding / decoding as part of (de)serialization.

use std::{borrow::Cow, fmt, marker::PhantomData, str};

use base64ct::Encoding;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Unexpected, Visitor},
};

/// A wrapper around `Vec<u8>` that (de)serializes from / to a base64 string.
///
/// The generic parameter `C` represents the base64 flavor.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Base64<C = base64ct::Base64> {
    bytes: Vec<u8>,
    // Invariant PhantomData, Send + Sync
    _phantom_conf: PhantomData<fn(C) -> C>,
}

pub type Base64UrlNoPad = Base64<base64ct::Base64UrlUnpadded>;

impl<C: Encoding> Base64<C> {
    /// Create a `Base64` instance from raw bytes, to be base64-encoded in
    /// serialization.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _phantom_conf: PhantomData,
        }
    }

    /// Get a reference to the raw bytes held by this `Base64` instance.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Encode the bytes contained in this `Base64` instance to unpadded base64.
    #[must_use]
    pub fn encode(&self) -> String {
        C::encode_string(self.as_bytes())
    }

    /// Get the raw bytes held by this `Base64` instance.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }

    /// Create a `Base64` instance containing an empty `Vec<u8>`.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Parse some base64-encoded data to create a `Base64` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not valid base64.
    pub fn parse(encoded: &str) -> Result<Self, base64ct::Error> {
        C::decode_vec(encoded).map(Self::new)
    }
}

impl<C: Encoding> fmt::Debug for Base64<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.encode().fmt(f)
    }
}

impl<C: Encoding> fmt::Display for Base64<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.encode().fmt(f)
    }
}

impl<'de, C: Encoding> Deserialize<'de> for Base64<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = deserialize_cow_str(deserializer)?;
        Self::parse(&encoded).map_err(de::Error::custom)
    }
}

impl<C: Encoding> Serialize for Base64<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encode())
    }
}

/// Deserialize a `Cow<'de, str>`.
///
/// Different from serde's implementation of `Deserialize` for `Cow` since it
/// borrows from the input when possible.
pub fn deserialize_cow_str<'de, D>(deserializer: D) -> Result<Cow<'de, str>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_string(CowStrVisitor)
}

struct CowStrVisitor;

impl<'de> Visitor<'de> for CowStrVisitor {
    type Value = Cow<'de, str>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Cow::Borrowed(v))
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match str::from_utf8(v) {
            Ok(s) => Ok(Cow::Borrowed(s)),
            Err(_) => Err(de::Error::invalid_value(Unexpected::Bytes(v), &self)),
        }
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Cow::Owned(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Cow::Owned(v))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match str::from_utf8(v) {
            Ok(s) => Ok(Cow::Owned(s.to_owned())),
            Err(_) => Err(de::Error::invalid_value(Unexpected::Bytes(v), &self)),
        }
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match String::from_utf8(v) {
            Ok(s) => Ok(Cow::Owned(s)),
            Err(e) => Err(de::Error::invalid_value(
                Unexpected::Bytes(&e.into_bytes()),
                &self,
            )),
        }
    }
}
