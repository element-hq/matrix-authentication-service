// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { TooltipProvider } from "@vector-im/compound-web";
import { beforeAll, describe, expect, it } from "vitest";
import { makeFragmentData } from "../../gql";
import { mockLocale } from "../../test-utils/mockLocale";
import render from "../../test-utils/render";
import CompatSessionDetail, { FRAGMENT } from "./CompatSessionDetail";

describe("<CompatSessionDetail>", () => {
  const baseSession = {
    id: "session-id",
    deviceId: "abcd1234",
    createdAt: "2023-06-29T03:35:17.451292+00:00",
    finishedAt: null,
    lastActiveIp: "1.2.3.4",
    lastActiveAt: "2023-07-29T03:35:17.451292+00:00",
    userAgent: null,
    ssoLogin: {
      id: "test-id",
      redirectUri: "https://element.io",
    },
  };

  beforeAll(() => mockLocale());

  it("renders a compatability session details", () => {
    const data = makeFragmentData({ ...baseSession }, FRAGMENT);

    const { container, getByText, queryByText } = render(
      <TooltipProvider>
        <CompatSessionDetail session={data} />
      </TooltipProvider>,
    );

    expect(container).toMatchSnapshot();
    expect(queryByText("Finished")).toBeFalsy();
    expect(getByText("Remove device")).toBeTruthy();
  });

  it("renders a compatability session without an ssoLogin", () => {
    const data = makeFragmentData(
      {
        ...baseSession,
        ssoLogin: null,
      },
      FRAGMENT,
    );

    const { container, getByText, queryByText } = render(
      <TooltipProvider>
        <CompatSessionDetail session={data} />
      </TooltipProvider>,
    );

    expect(container).toMatchSnapshot();
    expect(queryByText("Finished")).toBeFalsy();
    expect(getByText("Remove device")).toBeTruthy();
  });

  it("renders a finished compatability session details", () => {
    const data = makeFragmentData(
      {
        ...baseSession,
        finishedAt: "2023-07-29T03:35:17.451292+00:00",
      },
      FRAGMENT,
    );

    const { container, getByText, queryByText } = render(
      <TooltipProvider>
        <CompatSessionDetail session={data} />
      </TooltipProvider>,
    );

    expect(container).toMatchSnapshot();
    expect(getByText("Finished")).toBeTruthy();
    expect(queryByText("Remove device")).toBeFalsy();
  });
});
