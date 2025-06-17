// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { createLink } from "@tanstack/react-router";
import cx from "classnames";
import { forwardRef } from "react";

import type { DeviceType } from "../../gql/graphql";
import ClientAvatar from "../Session/ClientAvatar";
import DeviceTypeIcon from "../Session/DeviceTypeIcon";

import styles from "./SessionCard.module.css";

export const Root: React.FC<React.PropsWithChildren> = ({ children }) => (
  <section className={styles.sessionCardRoot}>{children}</section>
);

type BodyProps = React.PropsWithChildren<
  {
    disabled?: boolean;
    compact?: boolean;
    className?: string;
  } & React.AnchorHTMLAttributes<HTMLAnchorElement>
>;
export const LinkBody = createLink(
  forwardRef<HTMLAnchorElement, BodyProps>(
    ({ children, compact, className, ...props }, ref) => {
      const isDisabled = !!props.disabled || !!props["aria-disabled"] || false;
      return (
        <a
          className={cx(
            className,
            styles.sessionCard,
            compact && styles.compact,
            isDisabled && styles.disabled,
          )}
          {...props}
          ref={ref}
        >
          {children}
        </a>
      );
    },
  ),
);

export const Body: React.FC<BodyProps> = ({ children, compact, disabled }) => (
  <div
    className={cx(
      styles.sessionCard,
      compact && styles.compact,
      disabled && styles.disabled,
    )}
  >
    {children}
  </div>
);

type HeaderProps = React.PropsWithChildren<{ type: DeviceType }>;
export const Header: React.FC<HeaderProps> = ({ type, children }) => (
  <header className={styles.cardHeader}>
    <DeviceTypeIcon deviceType={type} />
    <div className={styles.content}>{children}</div>
  </header>
);

type NameProps = { name: string };
export const Name: React.FC<NameProps> = ({ name }) => (
  <div className={styles.name}>{name}</div>
);

type ClientProps = { name: string; logoUri?: string };
export const Client: React.FC<ClientProps> = ({ name, logoUri }) => (
  <div className={styles.client}>
    <ClientAvatar name={name} size="var(--cpd-space-5x)" logoUri={logoUri} />
    {name}
  </div>
);

export const Metadata: React.FC<React.PropsWithChildren> = ({ children }) => (
  <ul className={styles.metadata}>{children}</ul>
);

export const Info: React.FC<React.PropsWithChildren<{ label: string }>> = ({
  label,
  children,
}) => (
  <li>
    <div className={styles.key}>{label}</div>
    <div className={styles.value}>{children}</div>
  </li>
);

export const Action: React.FC<React.PropsWithChildren> = ({ children }) => (
  <div className={styles.action}>{children}</div>
);
