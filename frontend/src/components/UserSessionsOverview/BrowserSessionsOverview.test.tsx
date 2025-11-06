// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { makeFragmentData } from "../../gql";
import { DummyRouter } from "../../test-utils/router";

import BrowserSessionsOverview, { FRAGMENT } from "./BrowserSessionsOverview";

describe("BrowserSessionsOverview", () => {
  it("renders with no browser sessions", async () => {
    const user = makeFragmentData(
      {
        id: "user:123",
        browserSessions: {
          totalCount: 0,
        },
      },
      FRAGMENT,
    );
    const { container } = render(
      <DummyRouter>
        <BrowserSessionsOverview user={user} />
      </DummyRouter>,
    );

    expect(container).toMatchSnapshot();
  });

  it("renders with sessions", () => {
    const user = makeFragmentData(
      {
        id: "user:123",
        browserSessions: {
          totalCount: 2,
        },
      },
      FRAGMENT,
    );
    const { container } = render(
      <DummyRouter>
        <BrowserSessionsOverview user={user} />
      </DummyRouter>,
    );
    expect(container).toMatchSnapshot();
  });
});
