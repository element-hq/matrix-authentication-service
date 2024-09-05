// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute } from "@tanstack/react-router";

import { graphql } from "../gql";

export const QUERY = graphql(/* GraphQL */ `
  query PasswordRecoveryQuery {
    siteConfig {
      id
      ...PasswordCreationDoubleInput_siteConfig
    }
  }
`);

export const Route = createFileRoute("/password/recovery/")({
  validateSearch: (search) =>
    search as {
      ticket: string;
    },
  async loader({ context, abortController: { signal } }) {
    const queryResult = await context.client.query(
      QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (queryResult.error) throw queryResult.error;
  },
});
