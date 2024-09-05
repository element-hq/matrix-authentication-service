// Copyright (C) 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { action } from "@storybook/addon-actions";
import type { Meta, StoryObj } from "@storybook/react";

import EndSessionButton from "./EndSessionButton";

const endSession = action("end-session");

const meta = {
  title: "UI/Session/End Session Button",
  component: EndSessionButton,
  tags: ["autodocs"],
  args: {
    endSession: async (): Promise<void> => {
      await new Promise((resolve) => setTimeout(resolve, 300));
      endSession();
    },
  },
  argTypes: {
    children: { control: "text" },
  },
} satisfies Meta<typeof EndSessionButton>;

export default meta;
type Story = StoryObj<typeof EndSessionButton>;

export const Basic: Story = {};

export const WithChildren: Story = {
  args: {
    children:
      "Lorem ipsum dolor sit amet, officia excepteur ex fugiat reprehenderit enim labore culpa sint ad nisi Lorem pariatur mollit ex esse exercitation amet. Nisi anim cupidatat excepteur officia. Reprehenderit nostrud nostrud ipsum Lorem est aliquip amet voluptate voluptate dolor minim nulla est proident. Nostrud officia pariatur ut officia. Sit irure elit esse ea nulla sunt ex occaecat reprehenderit commodo officia dolor Lorem duis laboris cupidatat officia voluptate. Culpa proident adipisicing id nulla nisi laboris ex in Lorem sunt duis officia eiusmod. Aliqua reprehenderit commodo ex non excepteur duis sunt velit enim. Voluptate laboris sint cupidatat ullamco ut ea consectetur et est culpa et culpa duis.",
  },
};
