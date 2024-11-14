// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions } from "@tanstack/react-query";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { zodSearchValidator } from "@tanstack/router-zod-adapter";
import * as z from "zod";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query UserProfile {
    viewer {
      __typename
      ... on User {
        id
        primaryEmail {
          id
          ...UserEmail_email
        }

        ...UserEmailList_user
      }
    }

    siteConfig {
      emailChangeAllowed
      passwordLoginEnabled
      ...UserEmailList_siteConfig
      ...UserEmail_siteConfig
      ...PasswordChange_siteConfig
    }
  }
`);

export const query = queryOptions({
  queryKey: ["userProfile"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

const actionSchema = z
  .discriminatedUnion("action", [
    z.object({
      action: z.enum(["profile", "org.matrix.profile"]),
    }),
    z.object({
      action: z.enum(["sessions_list", "org.matrix.sessions_list"]),
    }),
    z.object({
      action: z.enum(["session_view", "org.matrix.session_view"]),
      device_id: z.string().optional(),
    }),
    z.object({
      action: z.enum(["session_end", "org.matrix.session_end"]),
      device_id: z.string().optional(),
    }),
    z.object({
      action: z.literal("org.matrix.cross_signing_reset"),
    }),
    z.object({
      action: z.undefined(),
    }),
  ])
  .catch({ action: undefined });

export const Route = createFileRoute("/_account/")({
  validateSearch: zodSearchValidator(actionSchema),

  beforeLoad({ search }) {
    switch (search.action) {
      case "profile":
      case "org.matrix.profile":
        throw redirect({ to: "/" });

      case "sessions_list":
      case "org.matrix.sessions_list":
        throw redirect({ to: "/sessions" });

      case "session_view":
      case "org.matrix.session_view":
        if (search.device_id)
          throw redirect({
            to: "/devices/$",
            params: { _splat: search.device_id },
          });
        throw redirect({ to: "/sessions" });

      case "session_end":
      case "org.matrix.session_end":
        if (search.device_id)
          throw redirect({
            to: "/devices/$",
            params: { _splat: search.device_id },
          });
        throw redirect({ to: "/sessions" });

      case "org.matrix.cross_signing_reset":
        throw redirect({
          to: "/reset-cross-signing",
          search: { deepLink: true },
        });
    }
  },

  loader: ({ context }) => context.queryClient.ensureQueryData(query),
});
