-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

ALTER TABLE oauth2_clients
  ADD COLUMN grant_type_token_exchange BOOLEAN NOT NULL DEFAULT FALSE;
