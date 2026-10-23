// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { QueryClient } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import {
  createRootRouteWithContext,
  type ErrorRouteComponent,
  HeadContent,
  Outlet,
} from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/react-router-devtools";
import { useLayoutEffect } from "react";
import GenericError from "../components/GenericError";
import Layout, { query } from "../components/Layout";
import NotFound from "../components/NotFound";
import { documentTitle } from "../utils/documentTitle";

const DocumentHead: React.FC = () => {
  // The server-rendered <title> stays until the router can set one, so that the
  // page still has a title if the app fails to load. Leaving it in after that
  // would shadow the <title> React hoists into <head>.
  useLayoutEffect(() => {
    document.querySelector("title[data-static]")?.remove();
  }, []);

  return <HeadContent />;
};

// Replaces the root component, so it needs its own <DocumentHead />. The
// not-found component renders inside the root <Outlet /> and doesn't.
const ErrorComponent: ErrorRouteComponent = ({ error }) => (
  <>
    <DocumentHead />
    <Layout>
      <GenericError error={error} />
    </Layout>
  </>
);

export const Route = createRootRouteWithContext<{
  queryClient: QueryClient;
  serverName: string;
}>()({
  head: ({ match }) => documentTitle(match),

  component: () => (
    <>
      <DocumentHead />
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

  async loader({ context }) {
    await context.queryClient.prefetchQuery(query);
  },

  errorComponent: ErrorComponent,

  notFoundComponent: () => (
    <Layout>
      <NotFound />
    </Layout>
  ),
});
