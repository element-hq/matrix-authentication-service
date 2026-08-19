// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { TooltipProvider } from "@vector-im/compound-web";
import { StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import * as v from "valibot";
import ErrorBoundary from "../components/ErrorBoundary";
import LoadingScreen from "../components/LoadingScreen";
import { setGraphqlEndpoint } from "../graphql";
import i18n, { setupI18n } from "../i18n";
import { makeRouter } from "../router";
import "./vendor.css";
import "./shared.css";

setupI18n();

const configSchema = v.object({
  root: v.optional(v.string(), "/"),
  graphqlEndpoint: v.optional(v.string(), "/graphql"),
});

const queryClient = new QueryClient({
  defaultOptions: {
    mutations: {
      throwOnError: true,
    },
  },
});

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("#root element not found");

const config = v.parse(configSchema, rootElement.dataset);
setGraphqlEndpoint(config.graphqlEndpoint);
const router = makeRouter(config.root, queryClient);

createRoot(rootElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ErrorBoundary>
        <TooltipProvider>
          <Suspense fallback={<LoadingScreen />}>
            <I18nextProvider i18n={i18n}>
              <RouterProvider router={router} />
            </I18nextProvider>
          </Suspense>
        </TooltipProvider>
      </ErrorBoundary>
    </QueryClientProvider>
  </StrictMode>,
);
