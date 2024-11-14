// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react";
import { expect, userEvent, waitFor, within } from "@storybook/test";
import i18n from "i18next";
import { App } from "./app";

const meta = {
  title: "Pages/Index",
  render: () => <App route="/" />,
  tags: ["!autodocs"],
} satisfies Meta;

export default meta;
type Story = StoryObj;

export const Index: Story = {};

export const EditProfile: Story = {
  play: async ({ canvasElement, globals }) => {
    const t = i18n.getFixedT(globals.locale);
    await i18n.loadLanguages(globals.locale);
    const page = within(document.body);
    const canvas = within(canvasElement);
    const button = await waitFor(() =>
      canvas.getByRole("button", { name: t("action.edit") }),
    );
    await userEvent.click(button);

    const dialog = page.getByRole("dialog");
    expect(dialog).toHaveTextContent(t("frontend.account.edit_profile.title"));
  },
};
