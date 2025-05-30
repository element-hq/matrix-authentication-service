// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import { action } from "storybook/actions";

import { Description, Dialog, Title } from "./Dialog";

const Template: React.FC<{
  title: string;
  description: string;
  asDrawer: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}> = ({ title, description, asDrawer, open, onOpenChange }) => (
  <Dialog asDrawer={asDrawer} open={open} onOpenChange={onOpenChange}>
    {title && <Title>{title}</Title>}
    <Description>{description}</Description>
  </Dialog>
);

const meta = {
  title: "UI/Dialog",
  component: Template,
  tags: ["autodocs"],
  args: {
    open: true,
    title: "Title",
    description: "Description",
    asDrawer: false,
    onOpenChange: action("onOpenChange"),
  },
  argTypes: {
    open: { control: "boolean" },
    title: { control: "text" },
    description: { control: "text" },
    asDrawer: { control: "boolean" },
    onOpenChange: { action: "onOpenChange" },
  },
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {};

export const LongText: Story = {
  args: {
    description:
      "Lorem ipsum dolor sit amet, officia excepteur ex fugiat reprehenderit enim labore culpa sint ad nisi Lorem pariatur mollit ex esse exercitation amet. Nisi anim cupidatat excepteur officia. Reprehenderit nostrud nostrud ipsum Lorem est aliquip amet voluptate voluptate dolor minim nulla est proident. Nostrud officia pariatur ut officia. Sit irure elit esse ea nulla sunt ex occaecat reprehenderit commodo officia dolor Lorem duis laboris cupidatat officia voluptate. Culpa proident adipisicing id nulla nisi laboris ex in Lorem sunt duis officia eiusmod. Aliqua reprehenderit commodo ex non excepteur duis sunt velit enim. Voluptate laboris sint cupidatat ullamco ut ea consectetur et est culpa et culpa duis.",
  },
};
