// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { createLink } from "@tanstack/react-router";
import CloseIcon from "@vector-im/compound-design-tokens/assets/web/icons/close";
import classNames from "classnames";
import { forwardRef } from "react";

import styles from "./Filter.module.css";

type Props = React.ComponentPropsWithRef<"a"> & {
  enabled?: boolean;
};

/**
 * A link which looks like a chip used when filtering items
 */
export const Filter = createLink(
  forwardRef<HTMLAnchorElement, Props>(function Filter(
    { children, enabled, ...props },
    ref,
  ) {
    const className = classNames(
      styles.filter,
      enabled ? styles.enabledFilter : styles.disabledFilter,
      props.className,
    );

    return (
      <a {...props} ref={ref} className={className}>
        {children}
        {enabled && <CloseIcon className={styles.closeIcon} />}
      </a>
    );
  }),
);
