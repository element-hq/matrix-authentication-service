// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute } from "@tanstack/react-router";
import { zodSearchValidator } from "@tanstack/router-zod-adapter";
import * as z from "zod";

import { queryOptions } from "@tanstack/react-query";
import { graphql } from "../gql";
import { graphqlClient } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query PasswordRecoveryQuery {
    siteConfig {
      id
      ...PasswordCreationDoubleInput_siteConfig
    }
  }
`);

export const query = queryOptions({
  queryKey: ["passwordRecovery"],
  queryFn: ({ signal }) => graphqlClient.request({ document: QUERY, signal }),
});

const schema = z.object({
  ticket: z.string(),
});

export const Route = createFileRoute("/password/recovery/")({
  validateSearch: zodSearchValidator(schema),

  loader: ({ context }) => context.queryClient.ensureQueryData(query),
});
