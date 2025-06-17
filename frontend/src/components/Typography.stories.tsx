// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";

import Typography from "./Typography";

const meta = {
  title: "UI/Typography",
  component: Typography,
  tags: ["autodocs"],
  args: {
    children: "Typography",
  },
} satisfies Meta<typeof Typography>;

export default meta;
type Story = StoryObj<typeof Typography>;

export const Basic: Story = {
  args: {
    children: "Hello",
    variant: "body",
  },
};

export const Headline: Story = {
  args: {
    children: "Headline",
    variant: "headline",
  },
};

export const Title: Story = {
  args: {
    children: "Title",
    variant: "title",
  },
};

export const Subtitle: Story = {
  args: {
    children: "Subtitle",
    variant: "subtitle",
  },
};

export const SubtitleSemiBold: Story = {
  args: {
    children: "Subtitle Semi Bold",
    variant: "subtitle",
    bold: true,
  },
};

export const Body: Story = {
  args: {
    children: "Body",
    variant: "body",
  },
};

export const BodySemiBold: Story = {
  args: {
    children: "Body",
    variant: "body",
    bold: true,
  },
};

export const Caption: Story = {
  args: {
    children: "Caption",
    variant: "caption",
  },
};

export const CaptionSemiBold: Story = {
  args: {
    children: "Caption",
    variant: "caption",
    bold: true,
  },
};

export const Micro: Story = {
  args: {
    children: "Micro",
    variant: "caption",
  },
};

export const MicroSemiBold: Story = {
  args: {
    children: "Micro",
    variant: "caption",
    bold: true,
  },
};
