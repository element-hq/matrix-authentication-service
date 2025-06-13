// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { QueryClient } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import {
  type ErrorRouteComponent,
  Outlet,
  createRootRouteWithContext,
} from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/react-router-devtools";
import GenericError from "../components/GenericError";
import Layout, { query } from "../components/Layout";
import NotFound from "../components/NotFound";

const ErrorComponent: ErrorRouteComponent = ({ error }) => (
  <Layout>
    <GenericError error={error} />
  </Layout>
);

export const Route = createRootRouteWithContext<{
  queryClient: QueryClient;
}>()({
  component: () => (
    <>
      <Outlet />

      {import.meta.env.DEV &&
        !import.meta.env.TEST &&
        !import.meta.env.STORYBOOK && (
          <>
            <TanStackRouterDevtools position="bottom-right" />
            <ReactQueryDevtools buttonPosition="top-right" />
          </>
        )}
    </>
  ),

  loader({ context }) {
    context.queryClient.ensureQueryData(query);
  },

  errorComponent: ErrorComponent,

  notFoundComponent: () => (
    <Layout>
      <NotFound />
    </Layout>
  ),
});
