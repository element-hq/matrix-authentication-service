// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { cacheExchange, createClient, fetchExchange } from "@urql/core";
import { devtoolsExchange } from "@urql/devtools";
import { refocusExchange } from "@urql/exchange-refocus";
import { requestPolicyExchange } from "@urql/exchange-request-policy";

import appConfig from "./config";

const exchanges = [
  // This sets the policy to 'cache-and-network' after 5 minutes
  requestPolicyExchange({
    ttl: 1000 * 60 * 5, // 5 minute
  }),

  // This refetches all queries when the tab is refocused
  refocusExchange(),

  // Simple cache
  cacheExchange,

  // Use `fetch` to execute the requests
  fetchExchange,
];

export const client = createClient({
  url: appConfig.graphqlEndpoint,
  suspense: true,
  // Add the devtools exchange in development
  exchanges: import.meta.env.DEV ? [devtoolsExchange, ...exchanges] : exchanges,
});
