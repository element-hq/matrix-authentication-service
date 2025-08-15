// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use rand_chacha::rand_core::CryptoRngCore;

use crate::clock::Clock;

/// A boxed [`Clock`]
pub type BoxClock = Box<dyn Clock + Send>;
/// A boxed random number generator
pub type BoxRng = Box<dyn CryptoRngCore + Send>;
