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
import GenericError from "../components/GenericError";
import Layout, { query } from "../components/Layout";
import NotFound from "../components/NotFound";
import i18n from "../i18n";

const ErrorComponent: ErrorRouteComponent = ({ error }) => (
  <Layout>
    <GenericError error={error} />
  </Layout>
);

export const Route = createRootRouteWithContext<{
  queryClient: QueryClient;
}>()({
  head: async () => {
    await i18n.loadNamespaces("translation");

    return {
      meta: [{ title: i18n.t("frontend.account.title") }],
    };
  },

  component: () => (
    <>
      <HeadContent />
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
