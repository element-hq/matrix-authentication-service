// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

#![deny(clippy::future_not_send)]
#![allow(clippy::module_name_repetitions)]

pub mod client_authorization;
pub mod cookies;
pub mod csrf;
pub mod error_wrapper;
pub mod fancy_error;
pub mod jwt;
pub mod language_detection;
pub mod sentry;
pub mod session;
pub mod user_authorization;

pub use axum;

pub use self::{
    error_wrapper::ErrorWrapper,
    fancy_error::{GenericError, InternalError},
    session::{SessionInfo, SessionInfoExt},
};
