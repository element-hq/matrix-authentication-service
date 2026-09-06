// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { QueryClient } from "@tanstack/react-query";
import { createRouter } from "@tanstack/react-router";
import LoadingScreen from "./components/LoadingScreen";
import { routeTree } from "./routeTree.gen";

export const makeRouter = (basepath: string, queryClient: QueryClient) =>
  createRouter({
    routeTree,
    scrollRestoration: true,
    basepath,
    defaultPendingComponent: LoadingScreen,
    defaultPreload: "intent",
    context: { queryClient },
  });

// Register the router instance for type safety
declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof makeRouter>;
  }
}
