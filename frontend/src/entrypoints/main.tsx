// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClient } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { Suspense } from "react";
import * as v from "valibot";
import LoadingScreen from "../components/LoadingScreen";
import { makeRouter } from "../router";
import { mountIsland } from "../utils/mountIsland";
import "./vendor.css";
import "./shared.css";

const schema = v.object({
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

void mountIsland({
  id: "root",
  schema,
  queryClient,
  children: (config) => (
    // The router lazy-loads its routes, so it needs a boundary of its own
    <Suspense fallback={<LoadingScreen />}>
      <RouterProvider router={makeRouter(config.root, queryClient)} />
    </Suspense>
  ),
});
