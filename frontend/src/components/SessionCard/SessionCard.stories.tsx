// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { Meta, StoryObj } from "@storybook/react-vite";
import IconSignOut from "@vector-im/compound-design-tokens/assets/web/icons/sign-out";
import { Button } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import type { DeviceType } from "../../gql/graphql";

import * as Card from "./SessionCard";

const Template: React.FC<{
  deviceType: DeviceType;
  deviceName: string;
  clientName?: string;
  disabled?: boolean;
}> = ({ deviceType, deviceName, clientName, disabled }) => {
  const { t } = useTranslation();
  return (
    <Card.Root>
      <Card.Body disabled={disabled}>
        <Card.Header type={deviceType}>
          <Card.Name name={deviceName} />
          {clientName && <Card.Client name={clientName} />}
        </Card.Header>
        <Card.Metadata>
          <Card.Info label="Last active">2 hours ago</Card.Info>
          <Card.Info label="Signed in">NOV 30, 2023</Card.Info>
          <Card.Info label="Device ID">XXXXXX</Card.Info>
        </Card.Metadata>
      </Card.Body>
      {!disabled && (
        <Card.Action>
          <Button kind="secondary" destructive size="sm" Icon={IconSignOut}>
            {t("frontend.end_session_button.text")}
          </Button>
        </Card.Action>
      )}
    </Card.Root>
  );
};

const meta = {
  title: "UI/Session/Card",
  component: Template,
  args: {
    disabled: false,
    deviceName: "MacBook Pro 16",
    clientName: "Firefox",
    deviceType: "PC",
  },
  argTypes: {
    deviceType: {
      control: "select",
      options: ["PC", "MOBILE", "TABLET", "UNKNOWN"],
    },
    disabled: { control: "boolean" },
    deviceName: { control: "text" },
    clientName: { control: "text" },
  },
} satisfies Meta<typeof Template>;

export default meta;
type Story = StoryObj<typeof Template>;

export const Basic: Story = {};
