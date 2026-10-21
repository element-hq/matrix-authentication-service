// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import styles from "./OrSeparator.module.css";

/** A horizontal rule with a label in the middle, typically "Or". */
const OrSeparator: React.FC<React.PropsWithChildren> = ({ children }) => (
  <div className={styles.orSeparator}>
    <hr />
    <p>{children}</p>
    <hr />
  </div>
);

export default OrSeparator;
