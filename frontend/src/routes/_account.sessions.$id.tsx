// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute, notFound } from "@tanstack/react-router";

import { graphql } from "../gql";

export const QUERY = graphql(/* GraphQL */ `
  query SessionDetailQuery($id: ID!) {
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

export const Route = createFileRoute("/_account/sessions/$id")({
  async loader({ context, params, abortController: { signal } }) {
    const result = await context.client.query(
      QUERY,
      { id: params.id },
      { fetchOptions: { signal } },
    );
    if (result.error) throw result.error;
    if (!result.data?.node) throw notFound();
  },
});
