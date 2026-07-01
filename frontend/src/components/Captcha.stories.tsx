import type { Meta, StoryObj } from "@storybook/react-vite";
import { Captcha } from "./Captcha";

const meta = {
  component: Captcha,
  title: "ui/Captcha",
} satisfies Meta<typeof Captcha>;

export default meta;
type Story = StoryObj<typeof Captcha>;

export const TurnstilePasses: Story = {
  name: "Cloudflare Turnstile (pass)",
  args: {
    config: {
      service: "cloudflare_turnstile",
      site_key: "1x00000000000000000000AA",
    },
  },
};

export const TurnstileFails: Story = {
  name: "Cloudflare Turnstile (fail)",
  args: {
    config: {
      service: "cloudflare_turnstile",
      site_key: "2x00000000000000000000AB",
    },
  },
};

export const ReCaptcha: Story = {
  name: "Google ReCaptcha",
  args: {
    config: {
      service: "recaptcha_v2",
      site_key: "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",
    },
  },
};

export const HCaptcha: Story = {
  name: "hCaptcha",
  args: {
    config: {
      service: "hcaptcha",
      site_key: "10000000-ffff-ffff-ffff-000000000001",
    },
  },
};
