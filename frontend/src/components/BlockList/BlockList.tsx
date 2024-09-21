// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import cx from "classnames";

import styles from "./BlockList.module.css";

type Props = React.PropsWithChildren<{
  className?: string;
}>;

const BlockList: React.FC<Props> = ({ className, children }: Props) => {
  return <div className={cx(styles.blockList, className)}>{children}</div>;
};

export default BlockList;
