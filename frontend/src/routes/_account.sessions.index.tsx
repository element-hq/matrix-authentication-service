// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useSuspenseQuery } from "@tanstack/react-query";
import { queryOptions } from "@tanstack/react-query";
import { notFound } from "@tanstack/react-router";
import { H3 } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import * as v from "valibot";
import { ButtonLink } from "../components/ButtonLink";
import CompatSession from "../components/CompatSession";
import EmptyState from "../components/EmptyState";
import Filter from "../components/Filter";
import OAuth2Session from "../components/OAuth2Session";
import Separator from "../components/Separator";
import BrowserSessionsOverview from "../components/UserSessionsOverview/BrowserSessionsOverview";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";
import { usePages } from "../pagination";
import {
  type AnyPagination,
  anyPaginationSchema,
  normalizePagination,
} from "../pagination";
import { getNinetyDaysAgo } from "../utils/dates";

const PAGE_SIZE = 6;

const QUERY = graphql(/* GraphQL */ `
  query SessionsOverview {
    viewer {
      __typename

      ... on User {
        id
        ...BrowserSessionsOverview_user
      }
    }
  }
`);

const query = queryOptions({
  queryKey: ["sessionsOverview"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

const LIST_QUERY = graphql(/* GraphQL */ `
  query AppSessionsList(
    $before: String
    $after: String
    $first: Int
    $last: Int
    $lastActive: DateFilter
  ) {
    viewer {
      __typename

      ... on User {
        id
        appSessions(
          before: $before
          after: $after
          first: $first
          last: $last
          lastActive: $lastActive
          state: ACTIVE
        ) {
          edges {
            cursor
            node {
              __typename
              ...CompatSession_session
              ...OAuth2Session_session
            }
          }

          totalCount
          pageInfo {
            startCursor
            endCursor
            hasNextPage
            hasPreviousPage
          }
        }
      }
    }
  }
`);

const listQuery = (pagination: AnyPagination, inactive: true | undefined) =>
  queryOptions({
    queryKey: ["appSessionList", inactive, pagination],
    queryFn: ({ signal }) =>
      graphqlRequest({
        query: LIST_QUERY,
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
    Promise.all([
      context.queryClient.ensureQueryData(query),
      context.queryClient.ensureQueryData(listQuery(pagination, inactive)),
    ]),

  component: Sessions,
});

// A type-safe way to ensure we've handled all session types
const unknownSessionType = (type: never): never => {
  throw new Error(`Unknown session type: ${type}`);
};

function Sessions(): React.ReactElement {
  const { t } = useTranslation();
  const { inactive, pagination } = Route.useLoaderDeps();
  const {
    data: { viewer },
  } = useSuspenseQuery(query);
  if (viewer.__typename !== "User") throw notFound();

  const { data } = useSuspenseQuery(listQuery(pagination, inactive));
  if (data.viewer.__typename !== "User") throw notFound();
  const appSessions = data.viewer.appSessions;

  const [backwardPage, forwardPage] = usePages(
    pagination,
    appSessions.pageInfo,
    PAGE_SIZE,
  );

  // We reverse the list as we are paginating backwards
  const edges = [...appSessions.edges].reverse();

  return (
    <div className="flex flex-col gap-6">
      <H3>{t("frontend.user_sessions_overview.heading")}</H3>
      <BrowserSessionsOverview user={viewer} />
      <Separator kind="section" />
      <div className="flex gap-2 justify-start items-center">
        <Filter
          to="/sessions"
          enabled={inactive}
          search={{ inactive: inactive ? undefined : true }}
        >
          {t("frontend.last_active.inactive_90_days")}
        </Filter>
      </div>
      {edges.map((session) => {
        const type = session.node.__typename;
        switch (type) {
          case "Oauth2Session":
            return (
              <OAuth2Session key={session.cursor} session={session.node} />
            );
          case "CompatSession":
            return (
              <CompatSession key={session.cursor} session={session.node} />
            );
          default:
            unknownSessionType(type);
        }
      })}

      {appSessions.totalCount === 0 && (
        <EmptyState>
          {inactive
            ? t(
                "frontend.user_sessions_overview.no_active_sessions.inactive_90_days",
              )
            : t("frontend.user_sessions_overview.no_active_sessions.default")}
        </EmptyState>
      )}

      {/* Only show the pagination buttons if there are pages to go to */}
      {(forwardPage || backwardPage) && (
        <div className="flex *:flex-1">
          <ButtonLink
            kind="secondary"
            size="sm"
            disabled={!forwardPage}
            to="/sessions"
            search={{ inactive, ...(forwardPage || pagination) }}
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
            to="/sessions"
            search={{ inactive, ...(backwardPage || pagination) }}
            resetScroll
          >
            {t("common.next")}
          </ButtonLink>
        </div>
      )}
    </div>
  );
}
