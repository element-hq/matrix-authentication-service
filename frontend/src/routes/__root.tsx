// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { Outlet, createRootRouteWithContext } from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/router-devtools";
import { Client } from "urql";

import Layout from "../components/Layout";
import NotFound from "../components/NotFound";

export const Route = createRootRouteWithContext<{
  client: Client;
}>()({
  component: () => (
    <>
      <Outlet />
      {import.meta.env.DEV && <TanStackRouterDevtools />}
    </>
  ),

  notFoundComponent: () => (
    <Layout>
      <NotFound />
    </Layout>
  ),
});
