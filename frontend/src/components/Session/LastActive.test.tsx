// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { composeStory } from "@storybook/react-vite";
import { render } from "@testing-library/react";
import { beforeAll, describe, expect, it } from "vitest";

import { mockLocale } from "../../test-utils/mockLocale";

import Meta, {
  ActiveNow,
  ActiveThreeDaysAgo,
  Basic,
  Inactive,
} from "./LastActive.stories";

describe("<LastActive", () => {
  beforeAll(() => mockLocale());

  it("renders an 'active now' timestamp", () => {
    const Component = composeStory(ActiveNow, { ...Meta });
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });

  it("renders a default timestamp", () => {
    const Component = composeStory(ActiveThreeDaysAgo, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });

  it("renders a relative timestamp", () => {
    const Component = composeStory(Basic, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });

  it("renders an inactive timestamp", () => {
    const Component = composeStory(Inactive, Meta);
    const { container } = render(<Component />);
    expect(container).toMatchSnapshot();
  });
});
