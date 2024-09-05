// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute, notFound } from "@tanstack/react-router";

import { graphql } from "../gql";

export const QUERY = graphql(/* GraphQL */ `
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

export const Route = createFileRoute("/password/change/")({
  async loader({ context, abortController: { signal } }) {
    const queryResult = await context.client.query(
      QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (queryResult.error) throw queryResult.error;
    if (queryResult.data?.viewer.__typename !== "User") throw notFound();
  },
});
