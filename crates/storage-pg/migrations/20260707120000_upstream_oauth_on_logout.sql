-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- This defines the behaviour towards the upstream provider when the user logs
-- out of MAS, as well as an optional override for the upstream provider's
-- OIDC RP-Initiated Logout `end_session_endpoint`.
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "on_logout" TEXT
    NOT NULL
    DEFAULT 'do_nothing',
  ADD COLUMN "end_session_endpoint_override" TEXT;
