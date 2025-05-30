// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import i18n from "i18next";
import { type GraphQLHandler, HttpResponse } from "msw";
import { expect, userEvent, waitFor, within } from "storybook/test";
import {
  CONFIG_FRAGMENT as ACCOUNT_DELETE_BUTTON_CONFIG_FRAGMENT,
  USER_FRAGMENT as ACCOUNT_DELETE_BUTTON_USER_FRAGMENT,
} from "../../src/components/AccountDeleteButton";
import { CONFIG_FRAGMENT as PASSWORD_CHANGE_CONFIG_FRAGMENT } from "../../src/components/AccountManagementPasswordPreview/AccountManagementPasswordPreview";
import { FRAGMENT as USER_EMAIL_FRAGMENT } from "../../src/components/UserEmail/UserEmail";
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
  mockUserEmailListQuery,
  mockUserProfileQuery,
} from "../../src/gql/graphql";
import { App } from "./app";

const meta = {
  title: "Pages/Index",
  render: () => <App route="/" />,
  tags: ["!autodocs"],
} satisfies Meta;

export default meta;
type Story = StoryObj;

const userProfileHandler = ({
  emailChangeAllowed,
  passwordLoginEnabled,
  passwordChangeAllowed,
  emailTotalCount,
  accountDeactivationAllowed,
  hasPassword,
}: {
  emailChangeAllowed: boolean;
  passwordLoginEnabled: boolean;
  passwordChangeAllowed: boolean;
  emailTotalCount: number;
  accountDeactivationAllowed: boolean;
  hasPassword: boolean;
}): GraphQLHandler =>
  mockUserProfileQuery(() =>
    HttpResponse.json({
      data: {
        viewerSession: {
          __typename: "BrowserSession",
          id: "session-id",
          user: Object.assign(
            {
              hasPassword,
              emails: {
                totalCount: emailTotalCount,
              },
            },
            makeFragmentData(
              {
                hasPassword,
              },
              ADD_USER_EMAIL_USER_FRAGMENT,
            ),
            makeFragmentData(
              {
                hasPassword,
              },
              USER_EMAIL_LIST_USER_FRAGMENT,
            ),
            makeFragmentData(
              {
                hasPassword,
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
            emailChangeAllowed,
            passwordLoginEnabled,
            accountDeactivationAllowed,
          },
          makeFragmentData(
            {
              emailChangeAllowed,
              passwordLoginEnabled,
            },
            ADD_USER_EMAIL_CONFIG_FRAGMENT,
          ),
          makeFragmentData(
            {
              emailChangeAllowed,
              passwordLoginEnabled,
            },
            USER_EMAIL_LIST_CONFIG_FRAGMENT,
          ),
          makeFragmentData(
            {
              passwordChangeAllowed,
            },
            PASSWORD_CHANGE_CONFIG_FRAGMENT,
          ),
          makeFragmentData(
            {
              passwordLoginEnabled,
            },
            ACCOUNT_DELETE_BUTTON_CONFIG_FRAGMENT,
          ),
        ),
      },
    }),
  );

const threeEmailsHandler = mockUserEmailListQuery(() =>
  HttpResponse.json({
    data: {
      viewer: {
        __typename: "User",
        emails: {
          edges: [
            "alice@example.com",
            "bob@example.com",
            "charlie@example.com",
          ].map((email) => ({
            cursor: email,
            node: {
              ...makeFragmentData(
                {
                  id: email,
                  email,
                },
                USER_EMAIL_FRAGMENT,
              ),
            },
          })),
          totalCount: 3,
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
);

export const Index: Story = {
  name: "One email address, email change allowed",
};

export const MultipleEmails: Story = {
  name: "Multiple email addresses, email change allowed",
  parameters: {
    msw: {
      handlers: [
        userProfileHandler({
          passwordLoginEnabled: true,
          passwordChangeAllowed: true,
          emailChangeAllowed: true,
          emailTotalCount: 3,
          accountDeactivationAllowed: true,
          hasPassword: true,
        }),
        threeEmailsHandler,
      ],
    },
  },
};

export const NoEmails: Story = {
  name: "No email address, email change not allowed",
  parameters: {
    msw: {
      handlers: [
        userProfileHandler({
          passwordLoginEnabled: true,
          passwordChangeAllowed: true,
          emailChangeAllowed: false,
          emailTotalCount: 0,
          accountDeactivationAllowed: true,
          hasPassword: true,
        }),
      ],
    },
  },
};

export const MultipleEmailsNoChange: Story = {
  name: "Multiple email addresses, email change not allowed",
  parameters: {
    msw: {
      handlers: [
        userProfileHandler({
          passwordLoginEnabled: true,
          passwordChangeAllowed: true,
          emailChangeAllowed: false,
          emailTotalCount: 3,
          accountDeactivationAllowed: true,
          hasPassword: true,
        }),
        threeEmailsHandler,
      ],
    },
  },
};

export const NoEmailChange: Story = {
  name: "One email address, email change not allowed",
  parameters: {
    msw: {
      handlers: [
        userProfileHandler({
          passwordLoginEnabled: true,
          passwordChangeAllowed: true,
          emailChangeAllowed: false,
          emailTotalCount: 1,
          accountDeactivationAllowed: true,
          hasPassword: true,
        }),
      ],
    },
  },
};

export const NoPasswordChange: Story = {
  name: "Password change not allowed",
  parameters: {
    msw: {
      handlers: [
        userProfileHandler({
          passwordLoginEnabled: true,
          passwordChangeAllowed: false,
          emailChangeAllowed: true,
          emailTotalCount: 1,
          accountDeactivationAllowed: true,
          hasPassword: true,
        }),
      ],
    },
  },
};

export const NoPasswordLogin: Story = {
  name: "Password login not allowed",
  parameters: {
    msw: {
      handlers: [
        userProfileHandler({
          passwordLoginEnabled: false,
          passwordChangeAllowed: false,
          emailChangeAllowed: true,
          emailTotalCount: 1,
          accountDeactivationAllowed: true,
          hasPassword: true,
        }),
      ],
    },
  },
};

export const NoPasswordNoEmailChangeNoAccountDeactivation: Story = {
  name: "No password, no email change, no account deactivation",
  parameters: {
    msw: {
      handlers: [
        userProfileHandler({
          passwordLoginEnabled: false,
          passwordChangeAllowed: false,
          emailChangeAllowed: false,
          emailTotalCount: 0,
          accountDeactivationAllowed: false,
          hasPassword: false,
        }),
      ],
    },
  },
};

export const NoAccountDeactivation: Story = {
  name: "No account deactivation",
  parameters: {
    msw: {
      handlers: [
        userProfileHandler({
          passwordLoginEnabled: true,
          passwordChangeAllowed: true,
          emailChangeAllowed: true,
          emailTotalCount: 1,
          accountDeactivationAllowed: false,
          hasPassword: true,
        }),
      ],
    },
  },
};

export const EditProfile: Story = {
  play: async ({ canvasElement, globals }) => {
    const t = i18n.getFixedT(globals.locale);
    await i18n.loadLanguages(globals.locale);
    const page = within(document.body);
    const canvas = within(canvasElement);
    const button = await waitFor(() =>
      canvas.getByRole("button", { name: t("action.edit") }),
    );
    await userEvent.click(button);

    const dialog = page.getByRole("dialog");
    expect(dialog).toHaveTextContent(t("frontend.account.edit_profile.title"));
  },
};
