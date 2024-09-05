// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { Meta, StoryObj } from "@storybook/react";
import { H2, Text } from "@vector-im/compound-web";

import Block from "../Block";

import BlockList from "./BlockList";

const meta = {
  title: "UI/Block List",
  component: BlockList,
} satisfies Meta<typeof BlockList>;

export default meta;

type Story = StoryObj<typeof meta>;

export const Basic: Story = {
  render: (args) => (
    <BlockList {...args}>
      <Block>
        <H2>Block 1</H2>
        <Text>Body 1</Text>
      </Block>
      <Block>
        <H2>Block 2</H2>
        <Text>Body 2</Text>
      </Block>
    </BlockList>
  ),
};
