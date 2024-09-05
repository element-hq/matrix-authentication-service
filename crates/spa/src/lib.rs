// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

#![deny(rustdoc::missing_crate_level_docs)]

//! A crate to help serve single-page apps built by Vite.

mod vite;

pub use self::vite::Manifest as ViteManifest;
