// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";

import { makeFragmentData } from "../../gql";

import Footer, { FRAGMENT } from "./Footer";

const Template: React.FC<{
  tosUri?: string;
  policyUri?: string;
  imprint?: string;
}> = ({ tosUri, policyUri, imprint }) => (
  <Footer
    siteConfig={makeFragmentData(
      { id: "1234", tosUri, policyUri, imprint },
      FRAGMENT,
    )}
  />
);

const meta = {
  title: "UI/Footer",
  component: Template,
  argTypes: {
    tosUri: {
      control: "text",
    },
    policyUri: {
      control: "text",
    },
    imprint: {
      control: "text",
    },
  },
  tags: ["autodocs"],
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {
  args: {
    tosUri: "https://matrix.org/legal/terms-and-conditions/",
    policyUri: "https://matrix.org/legal/privacy-notice/",
    imprint: "The Matrix.org Foundation C.I.C.",
  },
};

export const LinksOnly: Story = {
  args: {
    tosUri: "https://matrix.org/legal/terms-and-conditions/",
    policyUri: "https://matrix.org/legal/privacy-notice/",
  },
};

export const ImprintOnly: Story = {
  args: {
    imprint: "The Matrix.org Foundation C.I.C.",
  },
};

export const OneLink: Story = {
  args: {
    tosUri: "https://matrix.org/legal/terms-and-conditions/",
    imprint: "The Matrix.org Foundation C.I.C.",
  },
};
