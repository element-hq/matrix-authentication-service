// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";

import LoadingScreen from "./LoadingScreen";

const meta = {
  title: "UI/Loading Screen",
  component: LoadingScreen,
  parameters: {
    layout: "fullscreen",
  },
  tags: ["autodocs"],
} satisfies Meta<typeof LoadingScreen>;

export default meta;
type Story = StoryObj<typeof LoadingScreen>;

export const Basic: Story = {};
