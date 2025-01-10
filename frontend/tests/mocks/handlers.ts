// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { HttpResponse } from "msw";
import { CONFIG_FRAGMENT as PASSWORD_CHANGE_CONFIG_FRAGMENT } from "../../src/components/AccountManagementPasswordPreview/AccountManagementPasswordPreview";
import { FRAGMENT as FOOTER_FRAGMENT } from "../../src/components/Footer/Footer";
import {
  CONFIG_FRAGMENT as USER_EMAIL_CONFIG_FRAGMENT,
  FRAGMENT as USER_EMAIL_FRAGMENT,
} from "../../src/components/UserEmail/UserEmail";
import {
  CONFIG_FRAGMENT as USER_GREETING_CONFIG_FRAGMENT,
  FRAGMENT as USER_GREETING_FRAGMENT,
} from "../../src/components/UserGreeting/UserGreeting";
import { CONFIG_FRAGMENT as USER_EMAIL_LIST_CONFIG_FRAGMENT } from "../../src/components/UserProfile/UserEmailList";
import { makeFragmentData } from "../../src/gql";
import {
  mockCurrentUserGreetingQuery,
  mockCurrentViewerQuery,
  mockFooterQuery,
  mockUserEmailListQuery,
  mockUserProfileQuery,
} from "../../src/gql/graphql";

export const handlers = [
  mockFooterQuery(() =>
    HttpResponse.json({
      data: {
        siteConfig: {
          id: "siteConfig",

          ...makeFragmentData(
            {
              id: "siteConfig",
              policyUri: "https://matrix.org/policy",
              tosUri: "https://matrix.org/tos",
              imprint:
                "All Rights Reserved. The Super Chat name, logo and device are registered trade marks of BigCorp Ltd.",
            },
            FOOTER_FRAGMENT,
          ),
        },
      },
    }),
  ),

  mockCurrentViewerQuery(() =>
    HttpResponse.json({
      data: {
        viewer: {
          __typename: "User",
          id: "user-id",
        },
      },
    }),
  ),

  mockCurrentUserGreetingQuery(() =>
    HttpResponse.json({
      data: {
        viewerSession: {
          __typename: "BrowserSession",

          id: "session-id",
          user: Object.assign(
            makeFragmentData(
              {
                id: "user-id",
                matrix: {
                  mxid: "@alice:example.com",
                  displayName: "Alice",
                },
              },
              USER_GREETING_FRAGMENT,
            ),
          ),
        },

        siteConfig: makeFragmentData(
          {
            displayNameChangeAllowed: true,
          },
          USER_GREETING_CONFIG_FRAGMENT,
        ),
      },
    }),
  ),

  mockUserProfileQuery(() =>
    HttpResponse.json({
      data: {
        viewer: {
          __typename: "User",
          emails: {
            totalCount: 1,
          },
        },

        siteConfig: Object.assign(
          {
            emailChangeAllowed: true,
            passwordLoginEnabled: true,
          },
          makeFragmentData(
            {
              emailChangeAllowed: true,
            },
            USER_EMAIL_CONFIG_FRAGMENT,
          ),
          makeFragmentData(
            {
              emailChangeAllowed: true,
            },
            USER_EMAIL_LIST_CONFIG_FRAGMENT,
          ),
          makeFragmentData(
            {
              passwordChangeAllowed: true,
            },
            PASSWORD_CHANGE_CONFIG_FRAGMENT,
          ),
        ),
      },
    }),
  ),

  mockUserEmailListQuery(() =>
    HttpResponse.json({
      data: {
        viewer: {
          __typename: "User",
          emails: {
            edges: [
              {
                cursor: "primary-email-id",
                node: {
                  ...makeFragmentData(
                    {
                      id: "primary-email-id",
                      email: "alice@example.com",
                    },
                    USER_EMAIL_FRAGMENT,
                  ),
                },
              },
            ],
            totalCount: 1,
            pageInfo: {
              hasNextPage: false,
              hasPreviousPage: false,
              startCursor: null,
              endCursor: null,
            },
          },
        },
      },
    }),
  ),
];
