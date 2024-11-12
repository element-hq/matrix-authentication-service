// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { describe, expect, it } from "vitest";

import render from "../../test-utils/render";
import Block from "./Block";

describe("Block", () => {
  it("render <Block />", () => {
    const { asFragment } = render(<Block />);
    expect(asFragment()).toMatchSnapshot();
  });

  it("render <Block /> with children", () => {
    const { asFragment } = render(
      <Block>
        <h1>Title</h1>
        <p>Body</p>
      </Block>,
    );
    expect(asFragment()).toMatchSnapshot();
  });

  it("passes down the className prop", () => {
    const { asFragment } = render(<Block className="test" />);
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders with highlight", () => {
    const { asFragment } = render(<Block highlight />);
    expect(asFragment()).toMatchSnapshot();
  });
});
