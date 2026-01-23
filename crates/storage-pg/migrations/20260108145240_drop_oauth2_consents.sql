-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- We've stopped writing to this table in the following PR:
-- https://github.com/element-hq/matrix-authentication-service/pull/5405
-- This migration should be released in the version after that for safe rollout
DROP TABLE IF EXISTS oauth2_consents;
