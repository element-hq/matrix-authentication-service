// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import type { PropsWithChildren } from "react";

import SessionHeader from "./SessionHeader";

type Props = PropsWithChildren;

const Template: React.FC<Props> = ({ children }) => {
  return <SessionHeader to="/">{children}</SessionHeader>;
};

const meta = {
  title: "UI/Session/Session Detail/Header",
  component: Template,
  tags: ["autodocs"],
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {
  args: {
    children: <>Chrome on iOS</>,
  },
};
