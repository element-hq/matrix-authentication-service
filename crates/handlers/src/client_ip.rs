// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

/// The client IP address of the request.
///
/// This is set in the request extensions by the IP-detection middleware, ahead
/// of the rest of the request handling, so that the logging middleware and the
/// [`BoundActivityTracker`]/[`RequesterFingerprint`] extractors all observe the
/// same value without re-inferring it. It is `None` when the client IP could
/// not be determined.
///
/// [`BoundActivityTracker`]: crate::BoundActivityTracker
/// [`RequesterFingerprint`]: crate::RequesterFingerprint
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub Option<IpAddr>);
