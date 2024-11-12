// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll } from "vitest";
import { FRAGMENT } from "./src/components/Footer/Footer";
import { makeFragmentData } from "./src/gql";
import { mockFooterQuery } from "./src/gql/graphql";

const server = setupServer(
  mockFooterQuery(() =>
    HttpResponse.json({
      data: {
        siteConfig: {
          id: "siteConfig",

          ...makeFragmentData(
            {
              id: "siteConfig",
              policyUri: "https://matrix.org/policy",
              tosUri: "https://matrix.org/tos",
              imprint:
                "All Rights Reserved. The Super Chat name, logo and device are registered trade marks of BigCorp Ltd.",
            },
            FRAGMENT,
          ),
        },
      },
    }),
  ),
);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

//  Close server after all tests
afterAll(() => server.close());

// Reset handlers after each test `important for test isolation`
afterEach(() => server.resetHandlers());
