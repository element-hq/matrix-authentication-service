// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { TooltipProvider } from "@vector-im/compound-web";
import { StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import ErrorBoundary from "../components/ErrorBoundary";
import LoadingScreen from "../components/LoadingScreen";
import { queryClient } from "../graphql";
import i18n, { setupI18n } from "../i18n";
import { router } from "../router";
import "./shared.css";

setupI18n();

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
