// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import { sub } from "date-fns";

import DateTime from "./DateTime";

const now = new Date(2022, 11, 16, 15, 32, 10);

const meta = {
  title: "UI/DateTime",
  component: DateTime,
  tags: ["autodocs"],
  args: {
    now,
    datetime: sub(now, { minutes: 30 }),
  },
  argTypes: {
    now: {
      control: "date",
    },
    datetime: {
      control: "date",
    },
  },
} satisfies Meta<typeof DateTime>;

export default meta;
type Story = StoryObj<typeof DateTime>;

export const Basic: Story = {};

export const Now: Story = {
  args: {
    datetime: now,
  },
};

export const SecondsAgo: Story = {
  args: {
    datetime: sub(now, { seconds: 30 }),
  },
};

export const MinutesAgo: Story = {
  args: {
    datetime: sub(now, { minutes: 5 }),
  },
};

export const HoursAgo: Story = {
  args: {
    datetime: sub(now, { hours: 5 }),
  },
};
