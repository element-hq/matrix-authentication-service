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

export const query = (pagination: AnyPagination, inactive: true | undefined) =>
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

const searchSchema = z
  .object({
    inactive: z.literal(true).optional(),
  })
  .and(anyPaginationSchema);

export const Route = createFileRoute("/_account/sessions/browsers")({
  validateSearch: zodSearchValidator(searchSchema),

  loaderDeps: ({ search: { inactive, ...pagination } }) => ({
    inactive,
    pagination: normalizePagination(pagination, PAGE_SIZE, "backward"),
  }),

  loader: ({ context, deps: { inactive, pagination } }) =>
    context.queryClient.ensureQueryData(query(pagination, inactive)),
});
