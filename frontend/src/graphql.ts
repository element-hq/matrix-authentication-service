// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createClient, fetchExchange } from "@urql/core";
import { devtoolsExchange } from "@urql/devtools";
import { cacheExchange } from "@urql/exchange-graphcache";
import { refocusExchange } from "@urql/exchange-refocus";
import { requestPolicyExchange } from "@urql/exchange-request-policy";

import appConfig from "./config";
import type {
  MutationAddEmailArgs,
  MutationRemoveEmailArgs,
  MutationVerifyEmailArgs,
  RemoveEmailPayload,
  VerifyEmailPayload,
} from "./gql/graphql";
import schema from "./gql/schema";

const cache = cacheExchange({
  schema,
  keys: {
    // This is embedded in the `User` entity and has no ID
    MatrixUser: () => null,
  },
  updates: {
    Mutation: {
      addEmail: (result, args: MutationAddEmailArgs, cache, _info) => {
        const key = cache.keyOfEntity({
          __typename: "User",
          id: args.input.userId,
        });

        // Invalidate the emails field on the User object so that it gets refetched
        cache
          .inspectFields(key)
          .filter((field) => field.fieldName === "emails")
          .forEach((field) => {
            cache.invalidate(key, field.fieldName, field.arguments);
          });
      },

      removeEmail: (
        result: { removeEmail?: RemoveEmailPayload },
        args: MutationRemoveEmailArgs,
        cache,
        _info,
      ) => {
        // Invalidate the email entity
        cache.invalidate({
          __typename: "UserEmail",
          id: args.input.userEmailId,
        });

        // Let's try to figure out the userId to invalidate the emails field on the User object
        const userId = result.removeEmail?.user?.id;
        if (userId) {
          const key = cache.keyOfEntity({
            __typename: "User",
            id: userId,
          });

          // Invalidate the emails field on the User object so that it gets refetched
          cache
            .inspectFields(key)
            .filter((field) => field.fieldName === "emails")
            .forEach((field) => {
              cache.invalidate(key, field.fieldName, field.arguments);
            });
        }
      },

      verifyEmail: (
        result: { verifyEmail?: VerifyEmailPayload },
        args: MutationVerifyEmailArgs,
        cache,
        _info,
      ) => {
        // Invalidate the email entity
        cache.invalidate({
          __typename: "UserEmail",
          id: args.input.userEmailId,
        });

        // Let's try to figure out the userId to invalidate the emails field on the User object
        const userId = result.verifyEmail?.user?.id;
        if (userId) {
          const key = cache.keyOfEntity({
            __typename: "User",
            id: userId,
          });

          // Invalidate the emails field on the User object so that it gets refetched
          cache
            .inspectFields(key)
            .filter((field) => field.fieldName === "emails")
            .forEach((field) => {
              cache.invalidate(key, field.fieldName, field.arguments);
            });
        }
      },
    },
  },
});

const exchanges = [
  // This sets the policy to 'cache-and-network' after 5 minutes
  requestPolicyExchange({
    ttl: 1000 * 60 * 5, // 5 minute
  }),

  // This refetches all queries when the tab is refocused
  refocusExchange(),

  // The unified cache
  cache,

  // Use `fetch` to execute the requests
  fetchExchange,
];

export const client = createClient({
  url: appConfig.graphqlEndpoint,
  suspense: true,
  // Add the devtools exchange in development
  exchanges: import.meta.env.DEV ? [devtoolsExchange, ...exchanges] : exchanges,
});
