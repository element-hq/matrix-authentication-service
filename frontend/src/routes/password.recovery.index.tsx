// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions } from "@tanstack/react-query";
import { createFileRoute, notFound } from "@tanstack/react-router";
import * as v from "valibot";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query PasswordRecovery($ticket: String!) {
    siteConfig {
      ...RecoverPassword_siteConfig
    }

    userRecoveryTicket(ticket: $ticket) {
      status
      ...RecoverPassword_userRecoveryTicket
    }
  }
`);

export const query = (ticket: string) =>
  queryOptions({
    queryKey: ["passwordRecovery", ticket],
    queryFn: ({ signal }) =>
      graphqlRequest({ query: QUERY, signal, variables: { ticket } }),
  });

const schema = v.object({
  ticket: v.string(),
});

export const Route = createFileRoute("/password/recovery/")({
  validateSearch: schema,

  loaderDeps: ({ search: { ticket } }) => ({ ticket }),

  async loader({ context, deps: { ticket } }): Promise<void> {
    const { userRecoveryTicket } = await context.queryClient.ensureQueryData(
      query(ticket),
    );

    if (!userRecoveryTicket) {
      throw notFound();
    }
  },
});
