// Copyright (C) 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute, notFound } from "@tanstack/react-router";

import { graphql } from "../gql";

export const QUERY = graphql(/* GraphQL */ `
  query OAuth2ClientQuery($id: ID!) {
    oauth2Client(id: $id) {
      ...OAuth2Client_detail
    }
  }
`);

export const Route = createFileRoute("/clients/$id")({
  loader: async ({ context, params, abortController: { signal } }) => {
    const result = await context.client.query(
      QUERY,
      { id: params.id },
      { fetchOptions: { signal } },
    );
    if (result.error) throw result.error;
    if (!result.data?.oauth2Client) throw notFound();
  },
});
