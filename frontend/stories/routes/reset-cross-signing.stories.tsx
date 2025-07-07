// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import { delay, HttpResponse } from "msw";
import {
  mockAllowCrossSigningResetMutation,
  mockCurrentViewerQuery,
} from "../../src/gql/graphql";
import { App } from "./app";

const meta = {
  title: "Pages/Reset cross signing",
  tags: ["!autodocs"],
  parameters: {
    msw: {
      handlers: [
        mockAllowCrossSigningResetMutation(async () => {
          await delay();

          return HttpResponse.json({
            data: {
              allowUserCrossSigningReset: {
                user: {
                  id: "user-id",
                },
              },
            },
          });
        }),
      ],
    },
  },
} satisfies Meta;

export default meta;
type Story = StoryObj;

export const Index: Story = {
  render: () => <App route="/reset-cross-signing" />,
};

export const DeepLink: Story = {
  render: () => <App route="/reset-cross-signing?deepLink=true" />,
};

export const Success: Story = {
  render: () => <App route="/reset-cross-signing/success" />,
};

export const Cancelled: Story = {
  render: () => <App route="/reset-cross-signing/cancelled" />,
};

export const Errored: Story = {
  render: () => <App route="/reset-cross-signing" />,
  parameters: {
    msw: {
      handlers: [
        mockCurrentViewerQuery(() =>
          HttpResponse.json(
            {
              errors: [{ message: "Request failed" }],
            },
            { status: 400 },
          ),
        ),
      ],
    },
  },
};
