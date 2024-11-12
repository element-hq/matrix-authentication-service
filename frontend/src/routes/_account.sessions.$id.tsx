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
  query SessionDetail($id: ID!) {
    viewerSession {
      ... on Node {
        id
      }
    }

    node(id: $id) {
      __typename
      id
      ...CompatSession_detail
      ...OAuth2Session_detail
      ...BrowserSession_detail
    }
  }
`);

export const query = (id: string) =>
  queryOptions({
    queryKey: ["sessionDetail", id],
    queryFn: ({ signal }) =>
      graphqlRequest({ query: QUERY, signal, variables: { id } }),
  });

export const Route = createFileRoute("/_account/sessions/$id")({
  loader: ({ context, params }) =>
    context.queryClient.ensureQueryData(query(params.id)),
});
