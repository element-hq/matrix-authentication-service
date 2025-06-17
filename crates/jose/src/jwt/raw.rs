// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{borrow::Cow, ops::Deref};

use thiserror::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct RawJwt<'a> {
    inner: Cow<'a, str>,
    first_dot: usize,
    second_dot: usize,
}

impl RawJwt<'static> {
    pub(super) fn new(inner: String, first_dot: usize, second_dot: usize) -> Self {
        Self {
            inner: inner.into(),
            first_dot,
            second_dot,
        }
    }
}

impl std::fmt::Display for RawJwt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl<'a> RawJwt<'a> {
    pub fn header(&'a self) -> &'a str {
        &self.inner[..self.first_dot]
    }

    pub fn payload(&'a self) -> &'a str {
        &self.inner[self.first_dot + 1..self.second_dot]
    }

    pub fn signature(&'a self) -> &'a str {
        &self.inner[self.second_dot + 1..]
    }

    pub fn signed_part(&'a self) -> &'a str {
        &self.inner[..self.second_dot]
    }

    pub fn into_owned(self) -> RawJwt<'static> {
        RawJwt {
            inner: self.inner.into_owned().into(),
            first_dot: self.first_dot,
            second_dot: self.second_dot,
        }
    }
}

impl Deref for RawJwt<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("no dots found in JWT")]
    NoDots,

    #[error("only one dot found in JWT")]
    OnlyOneDot,

    #[error("too many dots in JWT")]
    TooManyDots,
}

impl<'a> From<RawJwt<'a>> for String {
    fn from(val: RawJwt<'a>) -> Self {
        val.inner.into()
    }
}

impl<'a> TryFrom<&'a str> for RawJwt<'a> {
    type Error = DecodeError;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let mut indices = value
            .char_indices()
            .filter_map(|(idx, c)| (c == '.').then_some(idx));

        let first_dot = indices.next().ok_or(DecodeError::NoDots)?;
        let second_dot = indices.next().ok_or(DecodeError::OnlyOneDot)?;

        if indices.next().is_some() {
            return Err(DecodeError::TooManyDots);
        }

        Ok(Self {
            inner: value.into(),
            first_dot,
            second_dot,
        })
    }
}

impl TryFrom<String> for RawJwt<'static> {
    type Error = DecodeError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut indices = value
            .char_indices()
            .filter_map(|(idx, c)| (c == '.').then_some(idx));

        let first_dot = indices.next().ok_or(DecodeError::NoDots)?;
        let second_dot = indices.next().ok_or(DecodeError::OnlyOneDot)?;

        if indices.next().is_some() {
            return Err(DecodeError::TooManyDots);
        }

        Ok(Self {
            inner: value.into(),
            first_dot,
            second_dot,
        })
    }
}
