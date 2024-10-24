// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! [`tower`] layers and services to help building HTTP client and servers

#![deny(rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]

mod ext;
mod reqwest;

pub use self::{
    ext::{set_propagator, CorsLayerExt},
    reqwest::{client as reqwest_client, RequestBuilderExt},
};
