// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";

import NavItem from "../NavItem";

import NavBar from "./NavBar";

const meta = {
  title: "UI/Nav Bar",
  component: NavBar,
  tags: ["autodocs"],
  render: (): React.ReactElement => (
    <NavBar>
      <NavItem to="/">Profile</NavItem>
      <NavItem to="/sessions">Sessions</NavItem>
    </NavBar>
  ),
} satisfies Meta<typeof NavBar>;

export default meta;
type Story = StoryObj<typeof NavBar>;

export const Basic: Story = {};
