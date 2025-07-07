// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  matchContext,
  RouterContextProvider,
  useRouterState,
} from "@tanstack/react-router";

const rootRoute = createRootRoute();
const index = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: () => null,
});

const router = createRouter({
  history: createMemoryHistory(),
  routeTree: rootRoute.addChildren([index]),
});
router.load();

const InnerProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const matchId = useRouterState({
    select: (s) => {
      return s.matches[0]?.id;
    },
  });

  return (
    <matchContext.Provider value={matchId}>{children}</matchContext.Provider>
  );
};

export const DummyRouter: React.FC<React.PropsWithChildren> = ({
  children,
}) => (
  <RouterContextProvider router={router}>
    <InnerProvider>{children}</InnerProvider>
  </RouterContextProvider>
);
