// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import classNames from "classnames";
import { forwardRef } from "react";

import styles from "./EmptyState.module.css";

/**
 * A component to display a message when a list is empty
 */
export const EmptyState = forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div">
>(function EmptyState({ children, ...props }, ref) {
  const className = classNames(styles.emptyState, props.className);
  return (
    <div ref={ref} {...props} className={className}>
      {children}
    </div>
  );
});
