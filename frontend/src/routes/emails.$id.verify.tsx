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
  query VerifyEmail($id: ID!) {
    userEmail(id: $id) {
      ...UserEmail_verifyEmail
    }
  }
`);

export const query = (id: string) =>
  queryOptions({
    queryKey: ["verifyEmail", id],
    queryFn: ({ signal }) =>
      graphqlRequest({ query: QUERY, signal, variables: { id } }),
  });

export const Route = createFileRoute("/emails/$id/verify")({
  loader: ({ context, params }) =>
    context.queryClient.ensureQueryData(query(params.id)),
});
