// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { SynapseUserId, UnixTimestamp } from "./index";

export interface SUser {
  name: SynapseUserId; // '@test2:localhost:8008'
  password_hash?: string;
  admin: number;
  is_guest: number;
  deactivated: number;
  creation_ts: UnixTimestamp;
  appservice_id?: string;
}
