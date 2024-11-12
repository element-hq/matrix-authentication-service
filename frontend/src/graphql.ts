// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import appConfig from "./config";
import type { TypedDocumentString } from "./gql/graphql";

let base: string;
if (import.meta.env.TEST && !window) {
  base = "http://localhost/";
} else {
  base = window.location.toString();
}

const graphqlEndpoint = new URL(appConfig.graphqlEndpoint, base).toString();

type RequestOptions<TResult, TVariables> = {
  query: TypedDocumentString<TResult, TVariables>;
  signal?: AbortSignal;
  // biome-ignore lint/suspicious/noExplicitAny: this is for inference
} & (TVariables extends Record<any, never>
  ? { variables?: TVariables }
  : { variables: TVariables });

export const graphqlRequest = async <TResult, TVariables>({
  query,
  variables,
  signal,
}: RequestOptions<TResult, TVariables>): Promise<TResult> => {
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

  const json = await response.json();
  if (json.errors) {
    throw new Error(JSON.stringify(json.errors));
  }

  return json.data;
};
