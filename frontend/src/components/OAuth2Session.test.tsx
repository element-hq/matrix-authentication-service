// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { beforeAll, describe, expect, it } from "vitest";
import { makeFragmentData } from "../gql";
import type { Oauth2ApplicationType } from "../gql/graphql";
import { mockLocale } from "../test-utils/mockLocale";
import render from "../test-utils/render";
import OAuth2Session, { FRAGMENT } from "./OAuth2Session";

describe("<OAuth2Session />", () => {
  const defaultSession = {
    id: "session-id",
    scope:
      "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:abcd1234",
    createdAt: "2023-06-29T03:35:17.451292+00:00",
    lastActiveIp: "1.2.3.4",
    client: {
      id: "test-id",
      clientId: "test-client-id",
      clientName: "Element",
      clientUri: "https://element.io",
      applicationType: "WEB" as Oauth2ApplicationType,
    },
  };

  const finishedAt = "2023-06-29T03:35:19.451292+00:00";

  beforeAll(() => mockLocale());

  it("renders an active session", () => {
    const session = makeFragmentData(defaultSession, FRAGMENT);

    const { asFragment } = render(<OAuth2Session session={session} />);
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders a finished session", () => {
    const session = makeFragmentData(
      {
        ...defaultSession,
        finishedAt,
      },
      FRAGMENT,
    );
    const { asFragment } = render(<OAuth2Session session={session} />);
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders correct icon for a native session", () => {
    const session = makeFragmentData(
      {
        ...defaultSession,
        finishedAt,
        client: {
          ...defaultSession.client,
          applicationType: "NATIVE",
        },
      },
      FRAGMENT,
    );
    const { asFragment } = render(<OAuth2Session session={session} />);
    expect(asFragment()).toMatchSnapshot();
  });
});
