// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { create } from "react-test-renderer";
import { describe, expect, it } from "vitest";

import LoadingScreen from "./LoadingScreen";

describe("LoadingScreen", () => {
  it("render <LoadingScreen />", () => {
    const component = create(<LoadingScreen />);
    const tree = component.toJSON();
    expect(tree).toMatchSnapshot();
  });
});
