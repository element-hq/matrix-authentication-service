// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

/// A structure which holds information about the running version of the app
#[derive(Debug, Clone, Copy)]
pub struct AppVersion(pub &'static str);
