// Copyright (C) 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import * as Collapsible from "@radix-ui/react-collapsible";
import IconChevronUp from "@vector-im/compound-design-tokens/assets/web/icons/chevron-up";
import classNames from "classnames";

import styles from "./Collapsible.module.css";

export const Trigger: React.FC<
  React.ComponentProps<typeof Collapsible.Trigger>
> = ({ children, className, ...props }) => {
  return (
    <Collapsible.Trigger
      {...props}
      className={classNames(styles.trigger, className)}
    >
      <div className={styles.triggerTitle}>{children}</div>
      <IconChevronUp
        className={styles.triggerIcon}
        height="24px"
        width="24px"
      />
    </Collapsible.Trigger>
  );
};

export const Content: React.FC<
  React.ComponentProps<typeof Collapsible.Content>
> = ({ className, ...props }) => {
  return (
    <Collapsible.Content
      {...props}
      className={classNames(styles.content, className)}
    />
  );
};

export const Root = Collapsible.Root;
