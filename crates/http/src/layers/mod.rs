// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

pub mod body_to_bytes_response;
pub mod bytes_to_body_request;
pub mod catch_http_codes;
pub mod form_urlencoded_request;
pub mod json_request;
pub mod json_response;

#[cfg(feature = "client")]
pub(crate) mod client;
