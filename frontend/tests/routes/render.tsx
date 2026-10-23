// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  type AnyRouter,
  createMemoryHistory,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import { type RenderResult, render } from "@testing-library/react";
import { TooltipProvider } from "@vector-im/compound-web";
import i18n from "i18next";
import { setupServer } from "msw/node";
import { I18nextProvider } from "react-i18next";
import { afterAll, afterEach, beforeAll } from "vitest";
import { routeTree } from "../../src/routeTree.gen";
import { handlers } from "../mocks/handlers";

export const server = setupServer(...handlers);

// Start server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

//  Close server after all tests
afterAll(() => server.close());

// Reset handlers after each test `important for test isolation`
afterEach(() => server.resetHandlers());

async function renderPage(
  route: string,
): Promise<RenderResult & { router: AnyRouter }> {
  // Create a new query client and a new router
  const queryClient = new QueryClient();
  const history = createMemoryHistory({ initialEntries: [route] });
  const router = createRouter({
    routeTree,
    context: { queryClient, serverName: "example.com" },
    history,
  });
  await router.load();
  // Since 1.170.19 only the failing route's errorComponent chunk is loaded. A
  // parent's code-split errorComponent then suspends inside RTL's act(), where
  // React never retries it, so load those chunks up front.
  // https://github.com/TanStack/router/issues/8792
  await Promise.all(
    router.state.matches.map((match) =>
      router.loadRouteChunk(router.routesById[match.routeId], "errorComponent"),
    ),
  );

  const result = render(
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <I18nextProvider i18n={i18n}>
          <RouterProvider router={router} />
        </I18nextProvider>
      </TooltipProvider>
    </QueryClientProvider>,
  );

  return { ...result, router };
}

export { renderPage };
