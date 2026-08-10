// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { QueryClient } from "@tanstack/react-query";
import { QueryClientProvider } from "@tanstack/react-query";
import { TooltipProvider } from "@vector-im/compound-web";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import * as v from "valibot";
import ErrorBoundary from "../components/ErrorBoundary";
import { setGraphqlEndpoint } from "../graphql";
import i18n, { setupI18n } from "../i18n";

/**
 * The server hands each island its parameters through `data-*` attributes; the
 * GraphQL endpoint is always one of them, so the helper can wire it up itself.
 */
type IslandSchema = v.GenericSchema<unknown, { graphqlEndpoint: string }>;

/**
 * Boot a React island rendered into a server-rendered page.
 *
 * The mount element's `data-*` attributes are parsed with `schema`, the locale
 * data is loaded, then `children` is rendered inside the shared provider stack.
 * Anything going wrong before the first render leaves the page with the
 * template's own `#<id>-error` notice instead of a half-mounted island.
 */
export const mountIsland = async <S extends IslandSchema>({
  id,
  schema,
  queryClient,
  children,
}: {
  /** Id of the mount element; its `#<id>-error` sibling is the fallback */
  id: string;
  schema: S;
  queryClient: QueryClient;
  children: (data: v.InferOutput<S>) => React.ReactNode;
}): Promise<void> => {
  const el = document.getElementById(id);

  try {
    if (!el) throw new Error(`#${id} element not found`);

    const data = v.parse(schema, el.dataset);
    // Set before any query runs, i.e. before the children render
    setGraphqlEndpoint(data.graphqlEndpoint);

    // Rendering before the locale data is in would flash the raw keys
    await setupI18n();

    createRoot(el).render(
      <StrictMode>
        <QueryClientProvider client={queryClient}>
          <ErrorBoundary>
            <TooltipProvider>
              <I18nextProvider i18n={i18n}>{children(data)}</I18nextProvider>
            </TooltipProvider>
          </ErrorBoundary>
        </QueryClientProvider>
      </StrictMode>,
    );
  } catch (error) {
    console.error(`Failed to mount #${id}`, error);
    if (el) el.hidden = true;
    document.getElementById(`${id}-error`)?.removeAttribute("hidden");
  }
};
