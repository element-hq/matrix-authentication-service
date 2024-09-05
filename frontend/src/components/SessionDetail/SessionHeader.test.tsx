// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { composeStory } from "@storybook/react";
import { render, cleanup } from "@testing-library/react";
import { describe, it, expect, afterEach } from "vitest";

import { DummyRouter } from "../../test-utils/router";

import Meta, { Basic } from "./SessionHeader.stories";

describe("<SessionHeader />", () => {
  afterEach(cleanup);
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
