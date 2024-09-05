// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { Heading } from "@vector-im/compound-web";
import cx from "classnames";
import { ReactNode } from "react";

import styles from "./Block.module.css";

type Props = React.PropsWithChildren<{
  title?: ReactNode;
  className?: string;
  highlight?: boolean;
}>;

const Block: React.FC<Props> = ({ children, className, highlight, title }) => {
  return (
    <div className={cx(styles.block, className)} data-active={highlight}>
      {title && (
        <Heading as="h4" size="sm" weight="semibold" className={styles.title}>
          {title}
        </Heading>
      )}

      {children}
    </div>
  );
};

export default Block;
