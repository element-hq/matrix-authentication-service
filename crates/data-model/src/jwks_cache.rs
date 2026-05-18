// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use chrono::{DateTime, Utc};
use mas_jose::jwk::PublicJsonWebKeySet;
use url::Url;

/// A row from the JWKS cache, content-addressed by its source URI.
#[derive(Debug, Clone)]
pub struct JwksCacheEntry {
    /// The URI the JWKS was fetched from.
    pub jwks_uri: Url,

    /// The cached JWKS body.
    pub jwks: PublicJsonWebKeySet,

    /// When the body was last fetched (or, on a `304 Not Modified`,
    /// last revalidated).
    pub fetched_at: DateTime<Utc>,

    /// Until when the cached body should be served without any HTTP traffic.
    /// Derived from the response's `Cache-Control: max-age` directive, clamped
    /// against the crate-level bounds.
    pub fresh_until: DateTime<Utc>,

    /// Until when the cached body may be served stale while a background
    /// refresh is in flight. Derived from `Cache-Control: stale-while-revalidate`.
    pub stale_until: Option<DateTime<Utc>>,

    /// The `ETag` from the most recent successful response, used to emit
    /// `If-None-Match` on conditional revalidation.
    pub etag: Option<String>,

    /// The `Last-Modified` from the most recent successful response, used to
    /// emit `If-Modified-Since` on conditional revalidation.
    pub last_modified: Option<String>,

    /// The last time a forced refresh was claimed by *any* replica. The
    /// cross-replica cooldown that bounds kid-miss and stale-while-revalidate
    /// refresh storms is anchored on this column.
    pub forced_refresh_at: Option<DateTime<Utc>>,

    /// The last time the cache entry was read. Drives the cleanup job which
    /// retires entries that haven't been touched in a long time.
    pub last_used_at: DateTime<Utc>,
}

impl JwksCacheEntry {
    /// Whether the cached body is still fresh at the given moment.
    #[must_use]
    pub fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        now < self.fresh_until
    }

    /// Whether the cached body is past `fresh_until` but still within the
    /// stale-while-revalidate window.
    #[must_use]
    pub fn is_stale_but_servable(&self, now: DateTime<Utc>) -> bool {
        !self.is_fresh(now) && self.stale_until.is_some_and(|until| now < until)
    }
}
