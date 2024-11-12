// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute } from "@tanstack/react-router";
import { zodSearchValidator } from "@tanstack/router-zod-adapter";
import * as z from "zod";

import { queryOptions } from "@tanstack/react-query";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";
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

export const query = queryOptions({
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

export const listQuery = (
  pagination: AnyPagination,
  inactive: true | undefined,
) =>
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

  loader: ({ context, deps: { inactive, pagination } }) =>
    Promise.all([
      context.queryClient.ensureQueryData(query),
      context.queryClient.ensureQueryData(listQuery(pagination, inactive)),
    ]),
});
