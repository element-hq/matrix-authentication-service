// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import i18n from "i18next";

type HeadMatch = {
  id: string;
  status: string;
  _notFound?: boolean;
  context: { serverName: string };
};

type HeadContext = {
  match: HeadMatch;
  matches: HeadMatch[];
};

/**
 * Build the `head` of a route, setting the document title to
 * "<page> – <server name>", or just the server name if no page is given.
 *
 * Error and not-found states override the page title, so that a broken page
 * doesn't keep the title of the page the user was trying to reach. This looks
 * at child matches too, since they may inherit this route's title.
 */
export const documentTitle = (
  { match, matches }: HeadContext,
  page?: string,
): { meta: { title: string }[] } => {
  const index = matches.findIndex((m) => m.id === match.id);
  const subtree = index === -1 ? [match] : matches.slice(index);

  let pageTitle = page;
  if (subtree.some((m) => m.status === "error")) {
    pageTitle = i18n.t("frontend.error.title");
  } else if (subtree.some((m) => m.status === "notFound" || m._notFound)) {
    pageTitle = i18n.t("frontend.page_titles.not_found");
  }

  const server = match.context.serverName;
  const title = pageTitle
    ? i18n.t("frontend.page_title", { page: pageTitle, server })
    : server;

  return { meta: [{ title }] };
};
