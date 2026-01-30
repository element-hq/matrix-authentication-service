-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- This removes unsupported threepids from deactivated users, as we forgot to do
-- it in the past. It's fine to do this in a migration as no one is reading from
-- this table and it is quite small. Follows up from:
-- https://github.com/element-hq/matrix-authentication-service/pull/5406
DELETE FROM user_unsupported_third_party_ids
USING users
WHERE users.deactivated_at IS NOT NULL
  AND users.user_id = user_unsupported_third_party_ids.user_id;
