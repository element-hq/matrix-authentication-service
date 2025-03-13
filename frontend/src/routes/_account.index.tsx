// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions } from "@tanstack/react-query";
import { createFileRoute, redirect } from "@tanstack/react-router";
import * as v from "valibot";
import { query as userEmailListQuery } from "../components/UserProfile/UserEmailList";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query UserProfile {
    viewerSession {
      __typename
      ... on BrowserSession {
        id
        user {
          ...AddEmailForm_user
          ...UserEmailList_user
          ...AccountDeleteButton_user
          hasPassword
          emails(first: 0) {
            totalCount
          }
        }
      }
    }

    siteConfig {
      emailChangeAllowed
      passwordLoginEnabled
      accountDeactivationAllowed
      ...AddEmailForm_siteConfig
      ...UserEmailList_siteConfig
      ...PasswordChange_siteConfig
      ...AccountDeleteButton_siteConfig
    }
  }
`);

export const query = queryOptions({
  queryKey: ["userProfile"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

const actionSchema = v.variant("action", [
  v.object({
    action: v.picklist(["profile", "org.matrix.profile"]),
  }),
  v.object({
    action: v.picklist(["sessions_list", "org.matrix.sessions_list"]),
  }),
  v.object({
    action: v.picklist(["session_view", "org.matrix.session_view"]),
    device_id: v.optional(v.string()),
  }),
  v.object({
    action: v.picklist(["session_end", "org.matrix.session_end"]),
    device_id: v.optional(v.string()),
  }),
  v.object({
    action: v.literal("org.matrix.cross_signing_reset"),
  }),
  v.partial(
    v.looseObject({
      action: v.never(),
    }),
  ),
]);

export const Route = createFileRoute("/_account/")({
  validateSearch: actionSchema,

  beforeLoad({ search }) {
    switch (search.action) {
      case "profile":
      case "org.matrix.profile":
        throw redirect({ to: "/", search: {} });

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

  loader: ({ context }) =>
    Promise.all([
      context.queryClient.ensureQueryData(userEmailListQuery()),
      context.queryClient.ensureQueryData(query),
    ]),
});
