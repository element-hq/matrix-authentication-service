// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { create } from "react-test-renderer";
import { Provider } from "urql";
import { describe, expect, it, beforeAll } from "vitest";
import { never } from "wonka";

import { makeFragmentData } from "../gql";
import { mockLocale } from "../test-utils/mockLocale";
import { DummyRouter } from "../test-utils/router";

import CompatSession, { FRAGMENT } from "./CompatSession";

describe("<CompatSession />", () => {
  const mockClient = {
    executeQuery: (): typeof never => never,
  };

  const baseSession = {
    id: "session-id",
    deviceId: "abcd1234",
    createdAt: "2023-06-29T03:35:17.451292+00:00",
    lastActiveIp: "1.2.3.4",
    ssoLogin: {
      id: "test-id",
      redirectUri: "https://element.io/",
    },
  };

  const finishedAt = "2023-06-29T03:35:19.451292+00:00";

  beforeAll(() => mockLocale());

  it("renders an active session", () => {
    const session = makeFragmentData(baseSession, FRAGMENT);
    const component = create(
      <Provider value={mockClient}>
        <DummyRouter>
          <CompatSession session={session} />
        </DummyRouter>
      </Provider>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });

  it("renders a finished session", () => {
    const session = makeFragmentData(
      {
        ...baseSession,
        finishedAt,
      },
      FRAGMENT,
    );
    const component = create(
      <Provider value={mockClient}>
        <DummyRouter>
          <CompatSession session={session} />
        </DummyRouter>
      </Provider>,
    );
    expect(component.toJSON()).toMatchSnapshot();
  });
});
