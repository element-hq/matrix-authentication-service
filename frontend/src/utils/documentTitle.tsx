// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { MakeRouteMatchUnion } from "@tanstack/react-router";
import i18n from "i18next";
import { useLayoutEffect } from "react";

declare module "@tanstack/react-router" {
  interface StaticDataRouteOption {
    // A function so that the translation is looked up when rendering, after
    // i18next has loaded
    title?: () => string;
  }
}

/**
 * Build the document title from the matched routes, from the deepest route up
 * to the service name, e.g. "Sessions • Your account • example.com".
 *
 * A route that failed or wasn't found replaces its own title and those of its
 * children, so a broken page doesn't keep the title of the page the user was
 * trying to reach. This only covers errors and not-found results from route
 * loading: a component that throws while rendering is caught by its route's
 * boundary without changing the match status, so the page keeps its title.
 */
export const titleFromMatches = (
  matches: MakeRouteMatchUnion[],
  serviceName: string,
): string => {
  const parts: string[] = [];
  for (const match of matches) {
    if (match.status === "error") {
      parts.push(i18n.t("frontend.error.title"));
      break;
    }
    if (match.status === "notFound" || match._notFound) {
      parts.push(i18n.t("frontend.page_titles.not_found"));
      break;
    }
    const title = match.staticData.title?.();
    if (title) parts.push(title);
  }

  return [...parts.reverse(), serviceName].join(" • ");
};

export const DocumentTitle: React.FC<{ children: string }> = ({ children }) => {
  // The server-rendered <title> stays until React renders one, so that the
  // page still has a title if the app fails to load. Once React hoists its own
  // <title> into <head>, the static one would shadow it, so it's taken out and
  // put back if this unmounts.
  useLayoutEffect(() => {
    const title = document.querySelector("title[data-static]");
    title?.remove();
    return () => {
      if (title) document.head.prepend(title);
    };
  }, []);

  return <title>{children}</title>;
};
