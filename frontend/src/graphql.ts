// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { ExecutionResult } from "graphql";
import appConfig from "./config";
import type { TypedDocumentString } from "./gql/graphql";

let base: string;
if (import.meta.env.TEST && !window) {
  base = "http://localhost/";
} else {
  base = window.location.toString();
}

const graphqlEndpoint = new URL(appConfig.graphqlEndpoint, base).toString();

type RequestOptions<TData, TVariables> = {
  query: TypedDocumentString<TData, TVariables>;
  signal?: AbortSignal;
  // biome-ignore lint/suspicious/noExplicitAny: this is for inference
} & (TVariables extends Record<any, never>
  ? { variables?: TVariables }
  : { variables: TVariables });

export const graphqlRequest = async <TData, TVariables>({
  query,
  variables,
  signal,
}: RequestOptions<TData, TVariables>): Promise<TData> => {
  const response = await fetch(graphqlEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query,
      variables,
    }),
    signal,
  });

  if (!response.ok) {
    throw new Error(`GraphQL request failed: ${response.status}`);
  }

  const json: ExecutionResult<TData> = await response.json();
  if (json.errors) {
    throw new Error(JSON.stringify(json.errors));
  }

  if (!json.data) {
    throw new Error("GraphQL request returned no data");
  }

  return json.data;
};
