// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { SRefreshToken } from "./SRefreshToken";

import { Id, SynapseUserId } from "./index";

/*
CREATE TABLE access_tokens (
    id bigint NOT NULL,
    user_id text NOT NULL,
    device_id text,
    token text NOT NULL,
    valid_until_ms bigint,
    puppets_user_id text,
    last_validated bigint,
    refresh_token_id bigint,
    used boolean
);
*/
export interface SAccessToken {
  id: Id<SAccessToken>;
  user_id: SynapseUserId;
  device_id: string;
  token: string;
  valid_until_ms?: number;
  puppets_user_id?: SynapseUserId;
  last_validated?: number;
  refresh_token_id?: Id<SRefreshToken>;
  used: boolean;
}
