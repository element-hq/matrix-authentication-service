-- Copyright 2026 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- A shared cache for JWKS responses fetched from remote URIs, used to verify
-- JWS-signed JWTs (private_key_jwt client auth, upstream OIDC ID tokens,
-- backchannel logout tokens). The table is content-addressed by the URI:
-- caching is a pure infrastructure concern; trust decisions about which keys
-- are acceptable for which purpose live one layer up.
--
-- The `fresh_until` window comes from the response's `Cache-Control: max-age`
-- directive (clamped against crate-level bounds); `stale_until` from
-- `stale-while-revalidate`. `etag`/`last_modified` enable conditional GETs on
-- revalidation. `forced_refresh_at` is the cross-replica coordination handle
-- for the kid-miss and stale-while-revalidate refresh paths: only one writer
-- per cooldown window can claim it. `last_used_at` drives the cleanup job and
-- is bumped lazily on read.
CREATE TABLE IF NOT EXISTS jwks_cache (
    jwks_uri          TEXT PRIMARY KEY,
    jwks              JSONB NOT NULL,
    fetched_at        TIMESTAMP WITH TIME ZONE NOT NULL,
    fresh_until       TIMESTAMP WITH TIME ZONE NOT NULL,
    stale_until       TIMESTAMP WITH TIME ZONE,
    etag              TEXT,
    last_modified     TEXT,
    forced_refresh_at TIMESTAMP WITH TIME ZONE,
    last_used_at      TIMESTAMP WITH TIME ZONE NOT NULL
);

-- The cleanup job scans by `last_used_at` to drop entries that haven't been
-- touched in 30+ days.
CREATE INDEX IF NOT EXISTS jwks_cache_last_used_at_idx
    ON jwks_cache (last_used_at);
