// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import { parseISO, subDays, subHours } from "date-fns";

import LastActive from "./LastActive";

const meta = {
  title: "UI/Session/Last active time",
  component: LastActive,
  argTypes: {
    lastActive: { control: { type: "date" } },
    now: { control: { type: "date" } },
  },
  tags: ["autodocs"],
} satisfies Meta<typeof LastActive>;

export default meta;
type Story = StoryObj<typeof LastActive>;

const now = parseISO("2023-09-18T01:12:00.000Z");

export const Basic: Story = {
  args: {
    // An hour ago
    lastActive: subHours(now, 1),
    now,
  },
};

export const ActiveThreeDaysAgo: Story = {
  args: {
    // Three days ago
    lastActive: subDays(now, 3),
    now,
  },
};

export const ActiveNow: Story = {
  args: {
    lastActive: now,
    now,
  },
};

export const Inactive: Story = {
  args: {
    // 91 days ago
    lastActive: subDays(now, 91),
    now,
  },
};
