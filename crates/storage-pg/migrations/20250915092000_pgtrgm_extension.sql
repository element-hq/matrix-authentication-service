-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- This enables the pg_trgm extension, which is used for search filters
-- Starting Posgres 16, this extension is marked as "trusted", meaning it can be
-- installed by non-superusers
CREATE EXTENSION IF NOT EXISTS pg_trgm;
