// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createRouter } from "@tanstack/react-router";
import { TooltipProvider } from "@vector-im/compound-web";
import { StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";

import ErrorBoundary from "./components/ErrorBoundary";
import GenericError from "./components/GenericError";
import LoadingScreen from "./components/LoadingScreen";
import config from "./config";
import i18n from "./i18n";
import { routeTree } from "./routeTree.gen";
import "./shared.css";

const queryClient = new QueryClient({
  defaultOptions: {
    mutations: {
      throwOnError: true,
    },
  },
});

// Create a new router instance
const router = createRouter({
  routeTree,
  basepath: config.root,
  defaultErrorComponent: GenericError,
  defaultPreload: "intent",
  defaultPendingMinMs: 0,
  context: { queryClient },
});

// Register the router instance for type safety
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ErrorBoundary>
        <TooltipProvider>
          <Suspense fallback={<LoadingScreen />}>
            <I18nextProvider i18n={i18n}>
              <RouterProvider router={router} context={{ queryClient }} />
            </I18nextProvider>
          </Suspense>
        </TooltipProvider>
      </ErrorBoundary>
    </QueryClientProvider>
  </StrictMode>,
);
