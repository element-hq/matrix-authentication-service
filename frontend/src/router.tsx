// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { createRouter } from "@tanstack/react-router";
import LoadingScreen from "./components/LoadingScreen";
import config from "./config";
import { queryClient } from "./graphql";
import { routeTree } from "./routeTree.gen";

// Create a new router instance
export const router = createRouter({
  routeTree,
  scrollRestoration: true,
  basepath: config.root,
  defaultPendingComponent: LoadingScreen,
  defaultPreload: "intent",
  context: { queryClient },
});

// Register the router instance for type safety
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
