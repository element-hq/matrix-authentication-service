// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { HttpResponse } from "msw";
import {
  CONFIG_FRAGMENT as ACCOUNT_DELETE_BUTTON_CONFIG_FRAGMENT,
  USER_FRAGMENT as ACCOUNT_DELETE_BUTTON_USER_FRAGMENT,
} from "../../src/components/AccountDeleteButton";
import { CONFIG_FRAGMENT as PASSWORD_CHANGE_CONFIG_FRAGMENT } from "../../src/components/AccountManagementPasswordPreview/AccountManagementPasswordPreview";
import { FRAGMENT as FOOTER_FRAGMENT } from "../../src/components/Footer/Footer";
import { FRAGMENT as USER_EMAIL_FRAGMENT } from "../../src/components/UserEmail/UserEmail";
import {
  CONFIG_FRAGMENT as USER_GREETING_CONFIG_FRAGMENT,
  FRAGMENT as USER_GREETING_FRAGMENT,
} from "../../src/components/UserGreeting/UserGreeting";
import {
  CONFIG_FRAGMENT as ADD_USER_EMAIL_CONFIG_FRAGMENT,
  USER_FRAGMENT as ADD_USER_EMAIL_USER_FRAGMENT,
} from "../../src/components/UserProfile/AddEmailForm";
import {
  CONFIG_FRAGMENT as USER_EMAIL_LIST_CONFIG_FRAGMENT,
  USER_FRAGMENT as USER_EMAIL_LIST_USER_FRAGMENT,
} from "../../src/components/UserProfile/UserEmailList";
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
        viewer: Object.assign(
          makeFragmentData(
            {
              __typename: "User",
              id: "user-id",
              matrix: {
                mxid: "@alice:example.com",
                displayName: "Alice",
              },
            },
            USER_GREETING_FRAGMENT,
          ),
        ),

        siteConfig: Object.assign(
          makeFragmentData(
            {
              displayNameChangeAllowed: true,
            },
            USER_GREETING_CONFIG_FRAGMENT,
          ),
        ),
      },
    }),
  ),

  mockUserProfileQuery(() =>
    HttpResponse.json({
      data: {
        viewerSession: {
          __typename: "BrowserSession",
          id: "browser-session-id",
          user: Object.assign(
            {
              hasPassword: true,
              emails: {
                totalCount: 1,
              },
            },
            makeFragmentData(
              {
                hasPassword: true,
              },
              ADD_USER_EMAIL_USER_FRAGMENT,
            ),
            makeFragmentData(
              {
                hasPassword: true,
              },
              USER_EMAIL_LIST_USER_FRAGMENT,
            ),
            makeFragmentData(
              {
                hasPassword: true,
                username: "alice",
                matrix: {
                  displayName: "Alice",
                  mxid: "@alice:example.com",
                },
              },
              ACCOUNT_DELETE_BUTTON_USER_FRAGMENT,
            ),
          ),
        },

        siteConfig: Object.assign(
          {
            emailChangeAllowed: true,
            passwordLoginEnabled: true,
            accountDeactivationAllowed: true,
          },
          makeFragmentData(
            {
              emailChangeAllowed: true,
              passwordLoginEnabled: true,
            },
            ADD_USER_EMAIL_CONFIG_FRAGMENT,
          ),
          makeFragmentData(
            {
              emailChangeAllowed: true,
              passwordLoginEnabled: true,
            },
            USER_EMAIL_LIST_CONFIG_FRAGMENT,
          ),
          makeFragmentData(
            {
              passwordChangeAllowed: true,
            },
            PASSWORD_CHANGE_CONFIG_FRAGMENT,
          ),
          makeFragmentData(
            {
              passwordLoginEnabled: true,
            },
            ACCOUNT_DELETE_BUTTON_CONFIG_FRAGMENT,
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
