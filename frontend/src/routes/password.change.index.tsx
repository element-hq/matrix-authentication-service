// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute } from "@tanstack/react-router";

import { queryOptions } from "@tanstack/react-query";
import { graphql } from "../gql";
import { graphqlClient } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query PasswordChangeQuery {
    viewer {
      __typename
      ... on Node {
        id
      }
    }

    siteConfig {
      ...PasswordCreationDoubleInput_siteConfig
    }
  }
`);

export const query = queryOptions({
  queryKey: ["passwordChange"],
  queryFn: ({ signal }) => graphqlClient.request({ document: QUERY, signal }),
});

export const Route = createFileRoute("/password/change/")({
  loader: ({ context }) => context.queryClient.ensureQueryData(query),
});
