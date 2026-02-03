// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![deny(missing_docs)]

//! AAGUID to human-readable name mapping for passkey authenticators
//!
//! This crate provides a lookup function to get the human-readable name for
//! a passkey authenticator based on its AAGUID (Authenticator Attestation
//! GUID).
//!
//! The data is generated from the
//! [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids)
//! repository.

use uuid::Uuid;

mod data;

/// Look up the human-readable name for an AAGUID
#[must_use]
pub fn lookup(aaguid: &Uuid) -> Option<&'static str> {
    data::AAGUIDS.get(aaguid).copied()
}
