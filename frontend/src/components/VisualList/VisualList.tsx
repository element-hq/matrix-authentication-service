// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { Text } from "@vector-im/compound-web";
import {
  FC,
  ForwardRefExoticComponent,
  PropsWithChildren,
  RefAttributes,
  SVGProps,
} from "react";

import styles from "./VisualList.module.css";

type Props = PropsWithChildren;

type ItemProps = {
  Icon: ForwardRefExoticComponent<
    Omit<SVGProps<SVGSVGElement>, "ref" | "children"> &
      RefAttributes<SVGSVGElement>
  >;
  iconColor?: string;
  label: string;
};

export const VisualListItem: FC<ItemProps> = ({
  Icon,
  iconColor,
  label,
}: ItemProps) => {
  return (
    <li className={styles.item}>
      <Icon color={iconColor ?? "var(--cpd-color-icon-tertiary)"} />
      <Text size="md" weight="medium">
        {label}
      </Text>
    </li>
  );
};

export const VisualList: React.FC<Props> = ({ children }: Props) => {
  return <ul className={styles.list}>{children}</ul>;
};
