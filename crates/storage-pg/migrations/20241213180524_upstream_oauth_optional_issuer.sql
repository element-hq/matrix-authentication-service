-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Make the issuer field in the upstream_oauth_providers table optional
ALTER TABLE "upstream_oauth_providers"
  ALTER COLUMN "issuer" DROP NOT NULL;
