// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { createLink } from "@tanstack/react-router";
import { Button } from "@vector-im/compound-web";
import cx from "classnames";
import { type PropsWithChildren, forwardRef } from "react";
import styles from "./ButtonLink.module.css";

type Props = {
  kind?: "primary" | "secondary" | "tertiary";
  size?: "sm" | "lg";
  Icon?: React.ComponentType<React.SVGAttributes<SVGElement>>;
  destructive?: boolean;
  disabled?: boolean;
  className?: string;
} & React.AnchorHTMLAttributes<HTMLAnchorElement>;

export const ButtonLink = createLink(
  forwardRef<HTMLAnchorElement, PropsWithChildren<Props>>(
    ({ children, className, ...props }, ref) => {
      const disabled = !!props.disabled || !!props["aria-disabled"] || false;
      return (
        <Button
          as="a"
          {...props}
          className={cx(styles.buttonLink, className)}
          disabled={disabled}
          ref={ref}
        >
          {children}
        </Button>
      );
    },
  ),
);
