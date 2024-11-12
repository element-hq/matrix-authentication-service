// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { describe, expect, it } from "vitest";

import render from "../../test-utils/render";
import LoadingScreen from "./LoadingScreen";

describe("LoadingScreen", () => {
  it("render <LoadingScreen />", () => {
    const { asFragment } = render(<LoadingScreen />);
    expect(asFragment()).toMatchSnapshot();
  });
});
