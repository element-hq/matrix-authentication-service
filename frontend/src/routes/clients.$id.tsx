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
  query OAuth2ClientQuery($id: ID!) {
    oauth2Client(id: $id) {
      ...OAuth2Client_detail
    }
  }
`);

export const query = (id: string) =>
  queryOptions({
    queryKey: ["oauth2Client", id],
    queryFn: ({ signal }) =>
      graphqlClient.request({ document: QUERY, variables: { id }, signal }),
  });

export const Route = createFileRoute("/clients/$id")({
  loader: ({ context, params }) =>
    context.queryClient.ensureQueryData(query(params.id)),
});
