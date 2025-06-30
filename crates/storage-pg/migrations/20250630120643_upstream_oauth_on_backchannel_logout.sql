-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- This defines the behavior when receiving a backchannel logout notification
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "on_backchannel_logout" TEXT
    NOT NULL
    DEFAULT 'do_nothing';
