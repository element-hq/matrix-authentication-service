// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react";
import { Provider } from "urql";
import { delay, fromValue, pipe } from "wonka";

import { makeFragmentData } from "../../gql";
import type { SetDisplayNameMutation } from "../../gql/graphql";

import UserGreeting, { CONFIG_FRAGMENT, FRAGMENT } from "./UserGreeting";

const Template: React.FC<{
  displayName?: string;
  mxid: string;
  displayNameChangeAllowed: boolean;
}> = ({ displayName, mxid, displayNameChangeAllowed }) => {
  const userId = "user id";

  const mockClient = {
    /* This will resolve after a small delay */
    // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
    executeMutation: () =>
      pipe(
        fromValue({
          data: {
            setDisplayName: {
              status: "SET",
              user: { id: userId, matrix: { displayName } },
            },
          },
        } satisfies { data: SetDisplayNameMutation }),
        delay(300),
      ),
  };

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
    <Provider value={mockClient}>
      <UserGreeting user={user} siteConfig={config} />
    </Provider>
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
