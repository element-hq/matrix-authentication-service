// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import i18n from "i18next";

type HeadMatch = {
  status: string;
  _notFound?: boolean;
  context: { serverName: string };
};

/**
 * Build the `head` of a route, setting the document title to
 * "<page> – <server name>", or just the server name if no page is given.
 *
 * Error and not-found states override the page title, so that a broken page
 * doesn't keep the title of the page the user was trying to reach.
 */
export const documentTitle = (
  match: HeadMatch,
  page?: string,
): { meta: { title: string }[] } => {
  let pageTitle = page;
  if (match.status === "error") {
    pageTitle = i18n.t("frontend.error.title");
  } else if (match.status === "notFound" || match._notFound) {
    pageTitle = i18n.t("frontend.page_titles.not_found");
  }

  const server = match.context.serverName;
  const title = pageTitle
    ? i18n.t("frontend.page_title", { page: pageTitle, server })
    : server;

  return { meta: [{ title }] };
};
