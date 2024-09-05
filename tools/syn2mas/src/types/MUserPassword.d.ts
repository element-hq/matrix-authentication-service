// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { MUser } from "./MUser";

import { UUID } from "./index";

export interface MUserPassword {
  user_password_id: UUID<MUserPassword>;
  user_id: UUID<MUser>;
  hashed_password: string;
  created_at: Date;
  version: number;
  upgraded_from_id?: UUID<MUserPassword>;
}
