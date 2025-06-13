// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import cx from "classnames";

import styles from "./PageHeading.module.css";

type Props = {
  Icon: React.ComponentType<React.SVGAttributes<SVGElement>>;
  invalid?: boolean;
  success?: boolean;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
};

const PageHeading: React.FC<Props> = ({
  Icon,
  invalid,
  success,
  title,
  subtitle,
}) => (
  <header className={styles.pageHeading}>
    <div
      className={cx(
        styles.icon,
        invalid && styles.invalid,
        success && styles.success,
      )}
    >
      <Icon />
    </div>

    <div className={styles.header}>
      <h1 className={styles.title}>{title}</h1>
      {subtitle && <p className={styles.text}>{subtitle}</p>}
    </div>
  </header>
);

export default PageHeading;
