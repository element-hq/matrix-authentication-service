// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconComputer from "@vector-im/compound-design-tokens/assets/web/icons/computer";
import IconMobile from "@vector-im/compound-design-tokens/assets/web/icons/mobile";
import IconUnknown from "@vector-im/compound-design-tokens/assets/web/icons/unknown";
import IconBrowser from "@vector-im/compound-design-tokens/assets/web/icons/web-browser";
import { FunctionComponent, SVGProps } from "react";
import { useTranslation } from "react-i18next";

import { DeviceType } from "../../gql/graphql";

import styles from "./DeviceTypeIcon.module.css";

const deviceTypeToIcon: Record<
  DeviceType,
  FunctionComponent<SVGProps<SVGSVGElement> & { title?: string | undefined }>
> = {
  [DeviceType.Unknown]: IconUnknown,
  [DeviceType.Pc]: IconComputer,
  [DeviceType.Mobile]: IconMobile,
  [DeviceType.Tablet]: IconBrowser,
};

const DeviceTypeIcon: React.FC<{ deviceType: DeviceType }> = ({
  deviceType,
}) => {
  const { t } = useTranslation();

  const Icon = deviceTypeToIcon[deviceType];

  const deviceTypeToLabel: Record<DeviceType, string> = {
    [DeviceType.Unknown]: t("frontend.device_type_icon_label.unknown"),
    [DeviceType.Pc]: t("frontend.device_type_icon_label.pc"),
    [DeviceType.Mobile]: t("frontend.device_type_icon_label.mobile"),
    [DeviceType.Tablet]: t("frontend.device_type_icon_label.tablet"),
  };

  const label = deviceTypeToLabel[deviceType];

  return <Icon className={styles.deviceTypeIcon} aria-label={label} />;
};

export default DeviceTypeIcon;
