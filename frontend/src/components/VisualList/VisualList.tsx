// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { Text } from "@vector-im/compound-web";
import type {
  FC,
  ForwardRefExoticComponent,
  ReactNode,
  RefAttributes,
  SVGProps,
} from "react";

import styles from "./VisualList.module.css";

type Props = {
  children: ReactNode;
};

export const VisualListItem: FC<{
  Icon: ForwardRefExoticComponent<
    Omit<SVGProps<SVGSVGElement>, "ref" | "children"> &
      RefAttributes<SVGSVGElement>
  >;
  iconColor?: string;
  label: string;
}> = ({ Icon, iconColor, label }) => {
  return (
    <li className={styles.item}>
      <Icon color={iconColor ?? "var(--cpd-color-icon-tertiary)"} />
      <Text size="md">{label}</Text>
    </li>
  );
};

export const VisualList: React.FC<Props> = ({ children }) => {
  return <ul className={styles.list}>{children}</ul>;
};
