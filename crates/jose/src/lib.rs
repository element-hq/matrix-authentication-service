// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![deny(rustdoc::broken_intra_doc_links)]
#![allow(clippy::module_name_repetitions)]

mod base64;
pub mod claims;
pub mod constraints;
pub mod jwa;
pub mod jwk;
pub mod jwt;

pub use self::base64::Base64;
