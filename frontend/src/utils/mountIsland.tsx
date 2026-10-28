// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { TooltipProvider } from "@vector-im/compound-web";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import * as v from "valibot";
import ErrorBoundary from "../components/ErrorBoundary";
import i18n, { setupI18n } from "../i18n";

/**
 * Boot a React island rendered into a server-rendered page.
 *
 * The mount element's `data-*` attributes are parsed with `schema`, the locale
 * data is loaded, then the tree returned by `render` is mounted inside the
 * shared provider stack. Anything going wrong before the first render leaves
 * the page with the template's own `#<id>-error` notice instead of a
 * half-mounted island.
 *
 * `render` is called exactly once, after the dataset is parsed and before
 * anything is mounted, so setup which needs the parsed data, such as
 * configuring the GraphQL endpoint, can happen at the top of it.
 */
export const mountIsland = async <T,>({
  id,
  schema,
  render,
}: {
  /** Id of the mount element; its `#<id>-error` sibling is the fallback */
  id: string;
  schema: v.GenericSchema<unknown, T>;
  render: (data: T) => React.ReactNode;
}): Promise<void> => {
  const el = document.getElementById(id);

  try {
    if (!el) throw new Error(`#${id} element not found`);

    const data = v.parse(schema, el.dataset);

    // Rendering before the locale data is in would flash the raw keys
    await setupI18n();

    createRoot(el).render(
      <StrictMode>
        <ErrorBoundary>
          <TooltipProvider>
            <I18nextProvider i18n={i18n}>{render(data)}</I18nextProvider>
          </TooltipProvider>
        </ErrorBoundary>
      </StrictMode>,
    );
  } catch (error) {
    console.error(`Failed to mount #${id}`, error);
    if (el) el.hidden = true;
    document.getElementById(`${id}-error`)?.removeAttribute("hidden");
  }
};
