// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { UUID } from "./index";

export interface MUser {
  user_id: UUID<MUser>;
  username: string; // localpart only without @
  created_at: Date;
  locked_at: Date | null;
  can_request_admin: boolean;
}
