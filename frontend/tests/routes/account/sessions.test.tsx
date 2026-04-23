// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { screen } from "@testing-library/react";
import { HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import {
  mockAppSessionsListQuery,
  mockSessionsOverviewQuery,
} from "../../../src/gql/graphql";
import { renderPage, server } from "../render";

describe("Account sessions page", () => {
  it("renders the page", async () => {
    const { asFragment } = await renderPage("/sessions");
    expect(asFragment()).toMatchSnapshot();
  });

  describe("session limit", () => {
    it("displays an error if they've hit the session soft_limit", async () => {
      server.use(
        mockSessionsOverviewQuery(() =>
          HttpResponse.json({
            data: {
              viewer: {
                __typename: "User",
                id: "123",
                // FIXME: Unclear how to deal with fragment masking (`$fragmentRefs`)
                browserSessions: {
                  totalCount: 3,
                },
                unfilteredAppSessions: {
                  // They have 12 sessions
                  totalCount: 12,
                },
              },
              siteConfig: {
                sessionLimit: {
                  // The limit is 12
                  softLimit: 12,
                },
              },
            },
          }),
        ),
      );

      server.use(
        mockAppSessionsListQuery(() =>
          HttpResponse.json({
            data: {
              viewer: {
                __typename: "User",
                id: "123",
                appSessions: {
                  totalCount: 12,
                  // Edge for each device on the page (6 per page):
                  // { cursor: "", node: { __typename: "Oauth2Session", ... } }
                  // { cursor: "", node: { __typename: "CompatSession",... } }
                  edges: Array.from(Array(6).keys()).map((index) => ({
                    cursor: `cursor${index}`,
                    node: {
                      __typename: "CompatSession",
                      id: `compat_session:${index}`,
                      createdAt: "2026-04-23T21:25:43.353610+00:00",
                      deviceId: `zzzZZZzzz${index}`,
                      finishedAt: null,
                      lastActiveIp: "127.0.0.1",
                      lastActiveAt: "2026-04-23T21:25:43.367193+00:00",
                      humanName: "Jungle Phone",
                      userAgent: {
                        name: "Chrome",
                        os: "Linux",
                        model: null,
                        deviceType: "PC",
                      },
                      ssoLogin: null,
                    },
                  })),
                  // Doesn't matter for test
                  pageInfo: {
                    startCursor: "foo",
                    endCursor: "bar",
                    hasNextPage: false,
                    hasPreviousPage: true,
                  },
                },
              },
            },
          }),
        ),
      );

      const { asFragment } = await renderPage("/sessions");

      // Make sure there is an error on the page
      screen.getByTestId("device-limit-error");

      // Sanity check page overall
      expect(asFragment()).toMatchSnapshot();
    });
  });
});
