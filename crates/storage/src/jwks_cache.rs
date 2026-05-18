// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Repository for the shared JWKS cache.
//!
//! See [`crate::JwksCacheRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mas_data_model::JwksCacheEntry;
use mas_jose::jwk::PublicJsonWebKeySet;
use url::Url;

use crate::repository_impl;

/// The values to upsert for a given JWKS cache entry. Carried as a parameter
/// rather than passed as positional arguments so the call site reads better,
/// and so it's easy to evolve without churning every implementation.
#[derive(Debug, Clone)]
pub struct JwksCacheUpsert<'a> {
    /// The JWKS as parsed by the fetcher (after filtering unsafe keys).
    pub jwks: &'a PublicJsonWebKeySet,

    /// When the body was fetched. For a `304 Not Modified` revalidation, this
    /// is the time of the revalidation, not the original fetch.
    pub fetched_at: DateTime<Utc>,

    /// When the cached body stops being fresh.
    pub fresh_until: DateTime<Utc>,

    /// When the cached body stops being acceptable as stale-while-revalidate.
    pub stale_until: Option<DateTime<Utc>>,

    /// The `ETag` (if any) to record for conditional revalidation.
    pub etag: Option<&'a str>,

    /// The `Last-Modified` (if any) to record for conditional revalidation.
    pub last_modified: Option<&'a str>,
}

/// A repository for the shared JWKS cache.
///
/// The cache is content-addressed by `jwks_uri`. Trust decisions about which
/// keys are acceptable for which purpose live one layer up; this repository is
/// pure infrastructure.
#[async_trait]
pub trait JwksCacheRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Look up the cached JWKS for a given URI.
    ///
    /// Returns `None` when no entry has ever been cached for this URI.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn get(&mut self, jwks_uri: &Url) -> Result<Option<JwksCacheEntry>, Self::Error>;

    /// Upsert a JWKS cache entry. Replaces the body and freshness metadata,
    /// but deliberately does not touch `forced_refresh_at` or `last_used_at`.
    ///
    /// On insert, `last_used_at` is initialised to `fetched_at` so a brand-new
    /// entry isn't immediately eligible for cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn upsert(
        &mut self,
        jwks_uri: &Url,
        values: JwksCacheUpsert<'_>,
    ) -> Result<(), Self::Error>;

    /// Attempt to claim the cross-replica forced-refresh cooldown for a URI.
    ///
    /// Returns `true` if this caller won the claim and should proceed with a
    /// network fetch, `false` if another replica claimed it within the
    /// cooldown window and the caller should stand down.
    ///
    /// If no row exists yet for the URI, returns `true` — the first replica to
    /// observe a kid miss for a brand-new URI gets to fetch.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn try_claim_forced_refresh(
        &mut self,
        jwks_uri: &Url,
        now: DateTime<Utc>,
        cooldown: Duration,
    ) -> Result<bool, Self::Error>;

    /// Bump `last_used_at` for the given URI, but only if the existing value
    /// is older than `threshold`. Best-effort: returns `Ok(())` even if no row
    /// was updated.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn touch(
        &mut self,
        jwks_uri: &Url,
        now: DateTime<Utc>,
        threshold: DateTime<Utc>,
    ) -> Result<(), Self::Error>;

    /// Delete a single cache entry by URI. Returns whether a row was removed.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn delete(&mut self, jwks_uri: &Url) -> Result<bool, Self::Error>;

    /// Delete all entries whose `last_used_at` is strictly older than `before`.
    /// Returns the number of rows removed.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn delete_unused_since(
        &mut self,
        before: DateTime<Utc>,
    ) -> Result<u64, Self::Error>;

    /// List all entries, ordered by URI. For operational visibility.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails.
    async fn list(&mut self) -> Result<Vec<JwksCacheEntry>, Self::Error>;
}

repository_impl!(JwksCacheRepository:
    async fn get(&mut self, jwks_uri: &Url) -> Result<Option<JwksCacheEntry>, Self::Error>;
    async fn upsert(
        &mut self,
        jwks_uri: &Url,
        values: JwksCacheUpsert<'_>,
    ) -> Result<(), Self::Error>;
    async fn try_claim_forced_refresh(
        &mut self,
        jwks_uri: &Url,
        now: DateTime<Utc>,
        cooldown: Duration,
    ) -> Result<bool, Self::Error>;
    async fn touch(
        &mut self,
        jwks_uri: &Url,
        now: DateTime<Utc>,
        threshold: DateTime<Utc>,
    ) -> Result<(), Self::Error>;
    async fn delete(&mut self, jwks_uri: &Url) -> Result<bool, Self::Error>;
    async fn delete_unused_since(
        &mut self,
        before: DateTime<Utc>,
    ) -> Result<u64, Self::Error>;
    async fn list(&mut self) -> Result<Vec<JwksCacheEntry>, Self::Error>;
);
