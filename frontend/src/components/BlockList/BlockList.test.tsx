// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { describe, expect, it } from "vitest";
import render from "../../test-utils/render";
import Block from "../Block";
import BlockList from "./BlockList";

describe("BlockList", () => {
  it("render an empty <BlockList />", () => {
    const { asFragment } = render(<BlockList />);
    expect(asFragment()).toMatchSnapshot();
  });

  it("render <BlockList /> with children", () => {
    const { asFragment } = render(
      <BlockList>
        <Block>Block 1</Block>
        <Block>Block 2</Block>
      </BlockList>,
    );
    expect(asFragment()).toMatchSnapshot();
  });

  it("passes down the className prop", () => {
    const { asFragment } = render(<BlockList className="foo" />);
    expect(asFragment()).toMatchSnapshot();
  });
});
