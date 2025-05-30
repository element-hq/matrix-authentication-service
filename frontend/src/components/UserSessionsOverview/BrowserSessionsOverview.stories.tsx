// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";

import { makeFragmentData } from "../../gql";
import { DummyRouter } from "../../test-utils/router";

import BrowserSessionsOverview, { FRAGMENT } from "./BrowserSessionsOverview";

type Props = {
  browserSessions: number;
};

const Template: React.FC<Props> = ({ browserSessions }) => {
  const data = makeFragmentData(
    {
      id: "user:123",
      browserSessions: {
        totalCount: browserSessions,
      },
    },
    FRAGMENT,
  );
  return (
    <DummyRouter>
      <BrowserSessionsOverview user={data} />
    </DummyRouter>
  );
};

const meta = {
  title: "Pages/User Sessions Overview/Browser Sessions",
  component: Template,
  tags: ["autodocs"],
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {
  args: {
    browserSessions: 2,
  },
};

export const Empty: Story = {
  args: {
    browserSessions: 0,
  },
};
