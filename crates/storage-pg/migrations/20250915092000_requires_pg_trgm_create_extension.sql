-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- This enables the pg_trgm extension, which is used for search filters
-- Starting Posgres 16, this extension is marked as "trusted", meaning it can be
-- installed by non-superusers

-- This migration is optional, and technically there is a good chance the
-- extension will be created anyway with mas_storage_pg::ExtensionDetection,
-- but we still create it here so that when using the static
-- mas_storage_pg::MIGRATOR (like in tests) we still create the extension.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
