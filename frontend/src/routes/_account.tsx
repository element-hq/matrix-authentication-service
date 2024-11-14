// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query CurrentUserGreeting {
    viewerSession {
      __typename

      ... on BrowserSession {
        id

        user {
          ...UnverifiedEmailAlert_user
          ...UserGreeting_user
        }
      }
    }

    siteConfig {
      ...UserGreeting_siteConfig
    }
  }
`);

export const query = queryOptions({
  queryKey: ["currentUserGreeting"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

export const Route = createFileRoute("/_account")({
  loader: ({ context }) => context.queryClient.ensureQueryData(query),
});
