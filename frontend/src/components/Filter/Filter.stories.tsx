// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";

import { Filter } from "./Filter";

const meta = {
  title: "UI/Filter",
  component: Filter,
  tags: ["autodocs"],
  args: {
    children: "Filter",
    enabled: false,
  },
  decorators: [
    (Story): React.ReactElement => (
      <div className="flex gap-4">
        <Story />
      </div>
    ),
  ],
} satisfies Meta<typeof Filter>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Disabled: Story = {
  args: {
    enabled: false,
  },
};

export const Enabled: Story = {
  args: {
    enabled: true,
  },
};
