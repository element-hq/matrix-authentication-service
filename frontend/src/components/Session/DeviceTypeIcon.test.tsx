// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { composeStory } from "@storybook/react";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import Meta, { Unknown, Pc, Mobile, Tablet } from "./DeviceTypeIcon.stories";

describe("<DeviceTypeIcon />", () => {
  it("renders unknown device type", () => {
    const Component = composeStory(Unknown, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
  it("renders mobile device type", () => {
    const Component = composeStory(Mobile, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
  it("renders pc device type", () => {
    const Component = composeStory(Pc, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
  it("renders tablet device type", () => {
    const Component = composeStory(Tablet, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
});
