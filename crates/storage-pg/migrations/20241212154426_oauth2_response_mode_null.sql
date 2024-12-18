-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Drop not null requirement on response mode, so we can ignore this query parameter.
ALTER TABLE "upstream_oauth_providers" ALTER COLUMN "response_mode" DROP NOT NULL;
