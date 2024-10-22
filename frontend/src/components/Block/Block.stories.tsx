// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react";
import { Body, H1, H5 } from "@vector-im/compound-web";

import Block from "./Block";

const meta = {
  title: "UI/Block",
  component: Block,
  tags: ["autodocs"],
} satisfies Meta<typeof Block>;

export default meta;
type Story = StoryObj<typeof Block>;

export const Basic: Story = {
  render: (args) => (
    <Block {...args}>
      <H1>Title</H1>
      <H5>Subtitle</H5>
      <Body justified>
        Lorem ipsum dolor sit amet, officia excepteur ex fugiat reprehenderit
        enim labore culpa sint ad nisi Lorem pariatur mollit ex esse
        exercitation amet. Nisi anim cupidatat excepteur officia. Reprehenderit
        nostrud nostrud ipsum Lorem est aliquip amet voluptate voluptate dolor
        minim nulla est proident. Nostrud officia pariatur ut officia. Sit irure
        elit esse ea nulla sunt ex occaecat reprehenderit commodo officia dolor
        Lorem duis laboris cupidatat officia voluptate. Culpa proident
        adipisicing id nulla nisi laboris ex in Lorem sunt duis officia eiusmod.
        Aliqua reprehenderit commodo ex non excepteur duis sunt velit enim.
        Voluptate laboris sint cupidatat ullamco ut ea consectetur et est culpa
        et culpa duis.
      </Body>
    </Block>
  ),
};
