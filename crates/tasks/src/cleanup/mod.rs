// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Database cleanup tasks
//!
//! This module contains tasks for cleaning up old data from the database.
//! Tasks are grouped by domain:
//!
//! - [`tokens`]: OAuth token cleanup (access and refresh tokens)
//! - [`sessions`]: Session cleanup (compat, `OAuth2`, user sessions and their
//!   IPs)
//! - [`oauth`]: OAuth grants and upstream OAuth cleanup
//! - [`user`]: User-related cleanup (registrations, recovery, email auth)
//! - [`misc`]: Miscellaneous cleanup (queue jobs, policy data)

mod misc;
mod oauth;
mod sessions;
mod tokens;
mod user;

pub(crate) const BATCH_SIZE: usize = 1000;
