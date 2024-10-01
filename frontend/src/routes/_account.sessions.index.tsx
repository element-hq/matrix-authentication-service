// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute, notFound } from "@tanstack/react-router";
import { zodSearchValidator } from "@tanstack/router-zod-adapter";
import * as z from "zod";

import { graphql } from "../gql";
import { anyPaginationSchema, normalizePagination } from "../pagination";
import { getNinetyDaysAgo } from "../utils/dates";

const PAGE_SIZE = 6;

export const QUERY = graphql(/* GraphQL */ `
  query SessionsOverviewQuery {
    viewer {
      __typename

      ... on User {
        id
        ...BrowserSessionsOverview_user
      }
    }
  }
`);

export const LIST_QUERY = graphql(/* GraphQL */ `
  query AppSessionsListQuery(
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

const searchSchema = z
  .object({
    inactive: z.literal(true).optional(),
  })
  .and(anyPaginationSchema);

export const Route = createFileRoute("/_account/sessions/")({
  validateSearch: zodSearchValidator(searchSchema),

  loaderDeps: ({ search: { inactive, ...pagination } }) => ({
    inactive,
    pagination: normalizePagination(pagination, PAGE_SIZE, "backward"),
  }),

  async loader({
    context,
    deps: { inactive, pagination },
    abortController: { signal },
  }) {
    const variables = {
      lastActive: inactive ? { before: getNinetyDaysAgo() } : undefined,
      ...pagination,
    };

    const [overview, list] = await Promise.all([
      context.client.query(QUERY, {}, { fetchOptions: { signal } }),
      context.client.query(LIST_QUERY, variables, {
        fetchOptions: { signal },
      }),
    ]);

    if (overview.error) throw overview.error;
    if (list.error) throw list.error;
    if (overview.data?.viewer?.__typename !== "User") throw notFound();
    if (list.data?.viewer?.__typename !== "User") throw notFound();
  },
});
