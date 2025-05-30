// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { composeStory } from "@storybook/react-vite";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DummyRouter } from "../../test-utils/router";

import Meta, { Basic } from "./SessionHeader.stories";

describe("<SessionHeader />", () => {
  it("renders a session header", () => {
    const Component = composeStory(Basic, Meta);
    const { container } = render(
      <DummyRouter>
        <Component />
      </DummyRouter>,
    );
    expect(container).toMatchSnapshot();
  });
});
