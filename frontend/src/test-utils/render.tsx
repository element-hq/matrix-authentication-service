// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render as testingLibraryRender } from "@testing-library/react";
import { DummyRouter } from "./router";

const client = new QueryClient();

const render = (
  ui: Parameters<typeof testingLibraryRender>[0],
  options: Parameters<typeof testingLibraryRender>[1] = {},
): ReturnType<typeof testingLibraryRender> =>
  testingLibraryRender(ui, {
    wrapper: ({ children }) => (
      <QueryClientProvider client={client}>
        <DummyRouter>{children}</DummyRouter>
      </QueryClientProvider>
    ),
    ...options,
  });

export default render;
