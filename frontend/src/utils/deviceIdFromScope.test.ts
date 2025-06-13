/* Copyright 2024, 2025 New Vector Ltd.
 * Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
 * Please see LICENSE files in the repository root for full details.
 */

import { describe, expect, it } from "vitest";

import { getDeviceIdFromScope } from "./deviceIdFromScope";

describe("getDeviceIdFromScope()", () => {
  it("returns deviceid when device is part of scope (unstable)", () => {
    const scope =
      "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:abcd1234";
    expect(getDeviceIdFromScope(scope)).toEqual("abcd1234");
  });

  it("returns deviceid when device is part of scope (stable)", () => {
    const scope =
      "openid urn:matrix:client:api:* urn:matrix:client:device:abcd1234";
    expect(getDeviceIdFromScope(scope)).toEqual("abcd1234");
  });

  it("returns undefined when device not part of scope", () => {
    const scope = "openid some:other:scope ";
    expect(getDeviceIdFromScope(scope)).toBeUndefined();
  });
});
