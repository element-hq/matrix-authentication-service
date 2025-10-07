// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// biome-ignore-all lint/a11y/useFocusableInteractive: this is a false positive
// biome-ignore-all lint/a11y/useAriaPropsForRole: this is a false positive
// biome-ignore-all lint/a11y/useSemanticElements: I don't want to use an <hr />

import cx from "classnames";
import { forwardRef } from "react";

import styles from "./Separator.module.css";

type Props = {
  kind?: "section";
} & React.HTMLAttributes<HTMLDivElement>;

const Separator = forwardRef<HTMLDivElement, Props>(
  ({ kind, className, ...props }: Props, ref) => (
    <div
      aria-orientation="horizontal"
      role="separator"
      className={cx(
        styles.separator,
        kind === "section" && styles.section,
        className,
      )}
      {...props}
      ref={ref}
    />
  ),
);

export default Separator;
