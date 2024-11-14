import { HttpResponse } from "msw";
import { CONFIG_FRAGMENT as PASSWORD_CHANGE_CONFIG_FRAGMENT } from "../../src/components/AccountManagementPasswordPreview/AccountManagementPasswordPreview";
import { FRAGMENT as FOOTER_FRAGMENT } from "../../src/components/Footer/Footer";
import { UNVERIFIED_EMAILS_FRAGMENT } from "../../src/components/UnverifiedEmailAlert/UnverifiedEmailAlert";
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

            makeFragmentData(
              {
                unverifiedEmails: {
                  totalCount: 0,
                },
              },
              UNVERIFIED_EMAILS_FRAGMENT,
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
          id: "user-id",
          primaryEmail: {
            id: "primary-email-id",
            ...makeFragmentData(
              {
                id: "primary-email-id",
                email: "alice@example.com",
                confirmedAt: new Date().toISOString(),
              },
              USER_EMAIL_FRAGMENT,
            ),
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
            makeFragmentData(
              {
                emailChangeAllowed: true,
              },
              USER_EMAIL_CONFIG_FRAGMENT,
            ),
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
        user: {
          id: "user-id",
          emails: {
            edges: [],
            totalCount: 0,
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
