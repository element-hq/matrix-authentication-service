-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

ALTER TABLE upstream_oauth_authorization_sessions
  ADD COLUMN unlinked_at TIMESTAMP WITH TIME ZONE;
