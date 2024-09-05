// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute, notFound } from "@tanstack/react-router";

import { graphql } from "../gql";

export const QUERY = graphql(/* GraphQL */ `
  query CurrentUserGreeting {
    viewerSession {
      __typename

      ... on BrowserSession {
        id

        user {
          id
          ...UnverifiedEmailAlert_user
          ...UserGreeting_user
        }
      }
    }

    siteConfig {
      id
      ...UserGreeting_siteConfig
    }
  }
`);

export const Route = createFileRoute("/_account")({
  loader: async ({ context, abortController: { signal } }) => {
    const result = await context.client.query(
      QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (result.error) throw result.error;
    if (result.data?.viewerSession.__typename !== "BrowserSession")
      throw notFound();
  },
});
