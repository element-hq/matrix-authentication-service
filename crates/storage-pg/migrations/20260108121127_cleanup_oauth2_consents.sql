-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- We've removed the idea of conditional consent (just go through the login if
-- we already consented in the past) but didn't do the cleanup in
-- https://github.com/element-hq/matrix-authentication-service/pull/4386

-- In this version we completely stopped writing to this table, so that it's
-- safe to completely drop in the next version
TRUNCATE TABLE oauth2_consents;

-- We stopped reading and writing in those columns a long time ago, so it's fine
-- to drop them now
ALTER TABLE oauth2_authorization_grants
  DROP COLUMN max_age,
  DROP COLUMN requires_consent;
