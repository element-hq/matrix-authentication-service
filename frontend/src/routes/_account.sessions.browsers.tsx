// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { notFound } from "@tanstack/react-router";
import { H5 } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import * as v from "valibot";
import BrowserSession from "../components/BrowserSession";
import { ButtonLink } from "../components/ButtonLink";
import EmptyState from "../components/EmptyState";
import Filter from "../components/Filter";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";
import {
  type AnyPagination,
  anyPaginationSchema,
  normalizePagination,
  usePages,
} from "../pagination";
import { getNinetyDaysAgo } from "../utils/dates";

const PAGE_SIZE = 6;

const QUERY = graphql(/* GraphQL */ `
  query BrowserSessionList(
    $first: Int
    $after: String
    $last: Int
    $before: String
    $lastActive: DateFilter
  ) {
    viewerSession {
      __typename
      ... on BrowserSession {
        id

        user {
          id

          browserSessions(
            first: $first
            after: $after
            last: $last
            before: $before
            lastActive: $lastActive
            state: ACTIVE
          ) {
            totalCount

            edges {
              cursor
              node {
                id
                ...BrowserSession_session
              }
            }

            pageInfo {
              hasNextPage
              hasPreviousPage
              startCursor
              endCursor
            }
          }
        }
      }
    }
  }
`);

const query = (pagination: AnyPagination, inactive: true | undefined) =>
  queryOptions({
    queryKey: ["browserSessionList", inactive, pagination],
    queryFn: ({ signal }) =>
      graphqlRequest({
        query: QUERY,
        variables: {
          lastActive: inactive ? { before: getNinetyDaysAgo() } : undefined,
          ...pagination,
        },
        signal,
      }),
  });

const searchSchema = v.intersect([
  v.object({
    inactive: v.optional(v.literal(true)),
  }),
  anyPaginationSchema,
]);

export const Route = createFileRoute({
  validateSearch: searchSchema,

  loaderDeps: ({ search: { inactive, ...pagination } }) => ({
    inactive,
    pagination: normalizePagination(pagination, PAGE_SIZE, "backward"),
  }),

  loader: ({ context, deps: { inactive, pagination } }) =>
    context.queryClient.ensureQueryData(query(pagination, inactive)),

  component: BrowserSessions,
});

function BrowserSessions(): React.ReactElement {
  const { t } = useTranslation();
  const { inactive, pagination } = Route.useLoaderDeps();

  const {
    data: { viewerSession },
  } = useSuspenseQuery(query(pagination, inactive));
  if (viewerSession.__typename !== "BrowserSession") throw notFound();

  const [backwardPage, forwardPage] = usePages(
    pagination,
    viewerSession.user.browserSessions.pageInfo,
    PAGE_SIZE,
  );

  // We reverse the list as we are paginating backwards
  const edges = [...viewerSession.user.browserSessions.edges].reverse();
  return (
    <div className="flex flex-col gap-6">
      <H5>{t("frontend.browser_sessions_overview.heading")}</H5>

      <div className="flex gap-2 items-start">
        <Filter
          to="/sessions/browsers"
          enabled={inactive}
          search={{ inactive: inactive ? undefined : true }}
        >
          {t("frontend.last_active.inactive_90_days")}
        </Filter>
      </div>

      {edges.map((n) => (
        <BrowserSession
          key={n.cursor}
          session={n.node}
          isCurrent={viewerSession.id === n.node.id}
        />
      ))}

      {viewerSession.user.browserSessions.totalCount === 0 && (
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
            resetScroll
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
            resetScroll
          >
            {t("common.next")}
          </ButtonLink>
        </div>
      )}
    </div>
  );
}
