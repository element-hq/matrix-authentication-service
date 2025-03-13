-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a table which stores the latest policy data
--
-- Every time the policy data is updated, it creates a new row, so that we keep
-- an history of the policy data, trace back which version of the data was used
-- on each evaluation.
CREATE TABLE IF NOT EXISTS policy_data (
    policy_data_id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    data JSONB NOT NULL
);
