// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { create } from "react-test-renderer";
import { describe, expect, it } from "vitest";

import Block from "../Block";

import BlockList from "./BlockList";

describe("BlockList", () => {
  it("render an empty <BlockList />", () => {
    const component = create(<BlockList />);
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("render <BlockList /> with children", () => {
    const component = create(
      <BlockList>
        <Block>Block 1</Block>
        <Block>Block 2</Block>
      </BlockList>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("passes down the className prop", () => {
    const component = create(<BlockList className="foo" />);
    expect(component.toJSON()).toMatchSnapshot();
  });
});
