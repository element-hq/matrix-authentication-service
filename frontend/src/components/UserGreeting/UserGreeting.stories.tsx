// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { makeFragmentData } from "../../gql";
import UserGreeting, { CONFIG_FRAGMENT, FRAGMENT } from "./UserGreeting";

const queryClient = new QueryClient();

const Template: React.FC<{
  displayName?: string;
  mxid: string;
  displayNameChangeAllowed: boolean;
}> = ({ displayName, mxid, displayNameChangeAllowed }) => {
  const user = makeFragmentData(
    {
      id: "user id",
      matrix: {
        mxid,
        displayName,
      },
    },
    FRAGMENT,
  );

  const config = makeFragmentData(
    {
      id: "site config id",
      displayNameChangeAllowed,
    },
    CONFIG_FRAGMENT,
  );

  return (
    <QueryClientProvider client={queryClient}>
      <UserGreeting user={user} siteConfig={config} />
    </QueryClientProvider>
  );
};

const meta = {
  title: "UI/User Greeting",
  component: Template,
  args: {
    displayNameChangeAllowed: true,
    displayName: "Kilgore Trout",
    mxid: "@kilgore:matrix.org",
  },
  argTypes: {
    displayNameChangeAllowed: {
      control: "boolean",
    },
    displayName: {
      control: "text",
    },
    mxid: {
      control: "text",
    },
  },
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {};

export const NoDisplayName: Story = {
  args: {
    displayName: undefined,
  },
};

export const DisplayNameChangeNotAllowed: Story = {
  args: {
    displayNameChangeAllowed: false,
  },
};
