// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react";

import { DeviceType } from "../../gql/graphql";

import DeviceTypeIcon from "./DeviceTypeIcon";

const meta = {
  title: "UI/Session/Device Type Icon",
  component: DeviceTypeIcon,
  tags: ["autodocs"],
  args: {
    deviceType: DeviceType.Unknown,
  },
  argTypes: {
    deviceType: {
      control: "select",
      options: [
        DeviceType.Unknown,
        DeviceType.Pc,
        DeviceType.Mobile,
        DeviceType.Tablet,
      ],
    },
  },
} satisfies Meta<typeof DeviceTypeIcon>;

export default meta;
type Story = StoryObj<typeof DeviceTypeIcon>;

export const Unknown: Story = {};

export const Pc: Story = {
  args: {
    deviceType: DeviceType.Pc,
  },
};
export const Mobile: Story = {
  args: {
    deviceType: DeviceType.Mobile,
  },
};
export const Tablet: Story = {
  args: {
    deviceType: DeviceType.Tablet,
  },
};
