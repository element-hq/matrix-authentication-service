// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import IconComputer from "@vector-im/compound-design-tokens/assets/web/icons/computer";
import IconMobile from "@vector-im/compound-design-tokens/assets/web/icons/mobile";
import IconUnknown from "@vector-im/compound-design-tokens/assets/web/icons/unknown";
import IconBrowser from "@vector-im/compound-design-tokens/assets/web/icons/web-browser";
import type { FunctionComponent, SVGProps } from "react";
import { useTranslation } from "react-i18next";

import type { DeviceType } from "../../gql/graphql";

import styles from "./DeviceTypeIcon.module.css";

const deviceTypeToIcon: Record<
  DeviceType,
  FunctionComponent<SVGProps<SVGSVGElement> & { title?: string | undefined }>
> = {
  UNKNOWN: IconUnknown,
  PC: IconComputer,
  MOBILE: IconMobile,
  TABLET: IconBrowser,
};

const DeviceTypeIcon: React.FC<{ deviceType: DeviceType }> = ({
  deviceType,
}) => {
  const { t } = useTranslation();

  const Icon = deviceTypeToIcon[deviceType];

  const deviceTypeToLabel: Record<DeviceType, string> = {
    UNKNOWN: t("frontend.device_type_icon_label.unknown"),
    PC: t("frontend.device_type_icon_label.pc"),
    MOBILE: t("frontend.device_type_icon_label.mobile"),
    TABLET: t("frontend.device_type_icon_label.tablet"),
  };

  const label = deviceTypeToLabel[deviceType];

  return <Icon className={styles.deviceTypeIcon} aria-label={label} />;
};

export default DeviceTypeIcon;
