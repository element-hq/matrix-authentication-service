-- Copyright 2025 The Matrix.org Foundation C.I.C.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

ALTER TABLE "upstream_oauth_providers"
    ADD COLUMN "allow_rp_initiated_logout" BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "end_session_endpoint_override" TEXT;
