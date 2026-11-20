-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Where the token's link sends its user once registered or signed in
ALTER TABLE "user_registration_tokens"
  ADD COLUMN "continue_url" TEXT;
