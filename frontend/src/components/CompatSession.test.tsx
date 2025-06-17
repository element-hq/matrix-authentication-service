// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { beforeAll, describe, expect, it } from "vitest";
import { makeFragmentData } from "../gql";
import { mockLocale } from "../test-utils/mockLocale";
import render from "../test-utils/render";
import CompatSession, { FRAGMENT } from "./CompatSession";

describe("<CompatSession />", () => {
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
    const { asFragment } = render(<CompatSession session={session} />);
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders a finished session", () => {
    const session = makeFragmentData(
      {
        ...baseSession,
        finishedAt,
      },
      FRAGMENT,
    );
    const { asFragment } = render(<CompatSession session={session} />);
    expect(asFragment()).toMatchSnapshot();
  });
});
