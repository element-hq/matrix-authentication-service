-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Drop the `NOT NULL` requirement on compat sessions, so we can import device-less access tokens from Synapse.
ALTER TABLE compat_sessions ALTER COLUMN device_id DROP NOT NULL;
