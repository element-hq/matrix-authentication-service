// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import { Suspense } from "react";
import { Captcha, CaptchaPlaceholder } from "./Captcha";

const meta = {
  component: Captcha,
  title: "ui/Captcha",
  decorators: [
    (Story) => (
      <Suspense fallback={<CaptchaPlaceholder service="hcaptcha" />}>
        <Story />
      </Suspense>
    ),
  ],
} satisfies Meta<typeof Captcha>;

export default meta;
type Story = StoryObj<typeof Captcha>;

// The stories below render a real widget, which loads the provider's SDK from
// its own CDN. They're kept out of the autodocs page, which would otherwise
// pull in all three SDKs at once on every visit.
const liveOnly = ["!autodocs"];

export const Placeholder: Story = {
  name: "Loading placeholder",
  render: () => <CaptchaPlaceholder service="hcaptcha" />,
};

export const NotConfigured: Story = {
  name: "No CAPTCHA configured",
  args: { config: null },
};

export const TurnstilePasses: Story = {
  name: "Cloudflare Turnstile (pass)",
  tags: liveOnly,
  args: {
    config: {
      service: "cloudflare_turnstile",
      site_key: "1x00000000000000000000AA",
    },
  },
};

export const TurnstileFails: Story = {
  name: "Cloudflare Turnstile (fail)",
  tags: liveOnly,
  args: {
    config: {
      service: "cloudflare_turnstile",
      site_key: "2x00000000000000000000AB",
    },
  },
};

export const ReCaptcha: Story = {
  name: "Google ReCaptcha",
  tags: liveOnly,
  args: {
    config: {
      service: "recaptcha_v2",
      site_key: "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",
    },
  },
};

export const HCaptcha: Story = {
  name: "hCaptcha",
  tags: liveOnly,
  args: {
    config: {
      service: "hcaptcha",
      site_key: "10000000-ffff-ffff-ffff-000000000001",
    },
  },
};
