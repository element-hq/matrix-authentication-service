// Copyright (C) 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createLazyFileRoute, notFound } from "@tanstack/react-router";
import { H5 } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import BlockList from "../components/BlockList";
import BrowserSession from "../components/BrowserSession";
import { ButtonLink } from "../components/ButtonLink";
import EmptyState from "../components/EmptyState";
import Filter from "../components/Filter";
import { type BackwardPagination, usePages } from "../pagination";
import { getNinetyDaysAgo } from "../utils/dates";

import { QUERY } from "./_account.sessions.browsers";

const PAGE_SIZE = 6;
const DEFAULT_PAGE: BackwardPagination = { last: PAGE_SIZE };

export const Route = createLazyFileRoute("/_account/sessions/browsers")({
  component: BrowserSessions,
});

function BrowserSessions(): React.ReactElement {
  const { t } = useTranslation();
  const { inactive, ...pagination } = Route.useLoaderDeps();

  const variables = {
    lastActive: inactive ? { before: getNinetyDaysAgo() } : undefined,
    ...pagination,
  };

  const [list] = useQuery({ query: QUERY, variables });
  if (list.error) throw list.error;
  const currentSession =
    list.data?.viewerSession.__typename === "BrowserSession"
      ? list.data.viewerSession
      : null;
  if (currentSession === null) throw notFound();

  const [backwardPage, forwardPage] = usePages(
    pagination,
    currentSession.user.browserSessions.pageInfo,
    PAGE_SIZE,
  );

  // We reverse the list as we are paginating backwards
  const edges = [...currentSession.user.browserSessions.edges].reverse();
  return (
    <BlockList>
      <H5>{t("frontend.browser_sessions_overview.heading")}</H5>

      <div className="flex gap-2 items-start">
        <Filter
          to="/sessions/browsers"
          enabled={inactive}
          search={{ ...DEFAULT_PAGE, inactive: inactive ? undefined : true }}
        >
          {t("frontend.last_active.inactive_90_days")}
        </Filter>
      </div>

      {edges.map((n) => (
        <BrowserSession
          key={n.cursor}
          session={n.node}
          isCurrent={currentSession.id === n.node.id}
        />
      ))}

      {currentSession.user.browserSessions.totalCount === 0 && (
        <EmptyState>
          {inactive
            ? t(
                "frontend.browser_sessions_overview.no_active_sessions.inactive_90_days",
              )
            : t(
                "frontend.browser_sessions_overview.no_active_sessions.default",
              )}
        </EmptyState>
      )}

      {/* Only show the pagination buttons if there are pages to go to */}
      {(forwardPage || backwardPage) && (
        <div className="flex *:flex-1">
          <ButtonLink
            kind="secondary"
            size="sm"
            disabled={!forwardPage}
            to="/sessions/browsers"
            search={forwardPage || pagination}
          >
            {t("common.previous")}
          </ButtonLink>

          {/* Spacer */}
          <div />

          <ButtonLink
            kind="secondary"
            size="sm"
            disabled={!backwardPage}
            to="/sessions/browsers"
            search={backwardPage || pagination}
          >
            {t("common.next")}
          </ButtonLink>
        </div>
      )}
    </BlockList>
  );
}
