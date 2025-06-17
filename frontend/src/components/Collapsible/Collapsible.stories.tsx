// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import * as Collapsible from "./Collapsible";

const meta = {
  title: "UI/Collapsible",
  component: Collapsible.Section,
  tags: ["autodocs"],
} satisfies Meta<typeof Collapsible.Section>;

export default meta;
type Story = StoryObj<typeof Collapsible.Section>;

export const Basic: Story = {
  args: {
    title: "Section name",
    description: "Optional section description",
    children: (
      <div>
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
        <p>Sed id felis eget orci aliquet tincidunt.</p>
      </div>
    ),
  },
};
