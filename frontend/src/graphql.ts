// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { GraphQLClient } from "graphql-request";

import appConfig from "./config";

let base: string;
if (import.meta.env.TEST && !window) {
  base = "http://localhost/";
} else {
  base = window.location.toString();
}

const graphqlEndpoint = new URL(appConfig.graphqlEndpoint, base).toString();

export const graphqlClient = new GraphQLClient(graphqlEndpoint);
