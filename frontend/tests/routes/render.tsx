// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router";
import { type RenderResult, render } from "@testing-library/react";
import { TooltipProvider } from "@vector-im/compound-web";
import i18n from "i18next";
import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { I18nextProvider } from "react-i18next";
import { afterAll, afterEach, beforeAll } from "vitest";
import { FRAGMENT } from "../../src/components/Footer/Footer";
import { makeFragmentData } from "../../src/gql";
import { mockFooterQuery } from "../../src/gql/graphql";
import { queryClient } from "../../src/graphql";
import { router } from "../../src/router";

const handlers = [
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
];

export const server = setupServer(...handlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

//  Close server after all tests
afterAll(() => server.close());

// Reset handlers after each test `important for test isolation`
afterEach(() => server.resetHandlers());

async function renderPage(route: string): Promise<RenderResult> {
  await router.load();
  const history = createMemoryHistory({
    initialEntries: [route],
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <I18nextProvider i18n={i18n}>
          <RouterProvider
            router={router}
            history={history}
            context={{ queryClient }}
          />
        </I18nextProvider>
      </TooltipProvider>
    </QueryClientProvider>,
  );
}

export { renderPage };
