// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { SynapseUserId } from "./index";

/*
CREATE TABLE user_threepids (
    user_id text NOT NULL,
    medium text NOT NULL,
    address text NOT NULL,
    validated_at bigint NOT NULL,
    added_at bigint NOT NULL
);
*/
export interface SUserThreePid {
  user_id: SynapseUserId;
  medium: string;
  address: string;
  validated_at: number;
  added_at: number;
}
