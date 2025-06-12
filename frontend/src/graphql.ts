// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClient } from "@tanstack/react-query";
import type { ExecutionResult } from "graphql";
import appConfig from "./config";
import type { TypedDocumentString } from "./gql/graphql";

let graphqlEndpoint: string;
if (import.meta.env.TEST && typeof window === "undefined") {
  graphqlEndpoint = new URL(
    appConfig.graphqlEndpoint,
    "http:://localhost/",
  ).toString();
} else {
  graphqlEndpoint = new URL(
    appConfig.graphqlEndpoint,
    window.location.toString(),
  ).toString();
}

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
  let response: Response;
  try {
    response = await fetch(graphqlEndpoint, {
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
  } catch (cause) {
    throw new Error(`GraphQL request to ${graphqlEndpoint} request failed`, {
      cause,
    });
  }

  if (!response.ok) {
    throw new Error(
      `GraphQL request to ${graphqlEndpoint} failed: ${response.status}`,
    );
  }

  const json: ExecutionResult<TData> = await response.json();
  if (json.errors) {
    throw new Error(JSON.stringify(json.errors));
  }

  if (!json.data) {
    throw new Error(`GraphQL request to ${graphqlEndpoint} returned no data`);
  }

  return json.data;
};

export const queryClient = new QueryClient({
  defaultOptions: {
    mutations: {
      throwOnError: true,
    },
  },
});
