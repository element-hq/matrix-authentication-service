// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { cleanup, render } from "@testing-library/react";
import { Provider } from "urql";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { never } from "wonka";

import { makeFragmentData } from "../../gql";
import { mockLocale } from "../../test-utils/mockLocale";
import { DummyRouter } from "../../test-utils/router";

import CompatSessionDetail, { FRAGMENT } from "./CompatSessionDetail";

describe("<CompatSessionDetail>", () => {
  const mockClient = {
    executeQuery: (): typeof never => never,
  };

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
  afterEach(cleanup);

  it("renders a compatability session details", () => {
    const data = makeFragmentData({ ...baseSession }, FRAGMENT);

    const { container, getByText, queryByText } = render(
      <Provider value={mockClient}>
        <DummyRouter>
          <CompatSessionDetail session={data} />
        </DummyRouter>
      </Provider>,
    );

    expect(container).toMatchSnapshot();
    expect(queryByText("Finished")).toBeFalsy();
    expect(getByText("Sign out")).toBeTruthy();
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
      <Provider value={mockClient}>
        <DummyRouter>
          <CompatSessionDetail session={data} />
        </DummyRouter>
      </Provider>,
    );

    expect(container).toMatchSnapshot();
    expect(queryByText("Finished")).toBeFalsy();
    expect(getByText("Sign out")).toBeTruthy();
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
      <Provider value={mockClient}>
        <DummyRouter>
          <CompatSessionDetail session={data} />
        </DummyRouter>
      </Provider>,
    );

    expect(container).toMatchSnapshot();
    expect(getByText("Finished")).toBeTruthy();
    expect(queryByText("Sign out")).toBeFalsy();
  });
});
