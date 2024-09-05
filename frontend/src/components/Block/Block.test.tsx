// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { create } from "react-test-renderer";
import { describe, expect, it } from "vitest";

import Block from "./Block";

describe("Block", () => {
  it("render <Block />", () => {
    const component = create(<Block />);
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("render <Block /> with children", () => {
    const component = create(
      <Block>
        <h1>Title</h1>
        <p>Body</p>
      </Block>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("passes down the className prop", () => {
    const component = create(<Block className="foo" />);
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("renders with highlight", () => {
    const component = create(<Block highlight />);
    expect(component.toJSON()).toMatchSnapshot();
  });
});
