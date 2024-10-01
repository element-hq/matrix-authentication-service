// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute } from "@tanstack/react-router";
import { zodSearchValidator } from "@tanstack/router-zod-adapter";
import * as z from "zod";

import { graphql } from "../gql";

export const QUERY = graphql(/* GraphQL */ `
  query PasswordRecoveryQuery {
    siteConfig {
      id
      ...PasswordCreationDoubleInput_siteConfig
    }
  }
`);

const schema = z.object({
  ticket: z.string(),
});

export const Route = createFileRoute("/password/recovery/")({
  validateSearch: zodSearchValidator(schema),

  async loader({ context, abortController: { signal } }) {
    const queryResult = await context.client.query(
      QUERY,
      {},
      { fetchOptions: { signal } },
    );
    if (queryResult.error) throw queryResult.error;
  },
});
