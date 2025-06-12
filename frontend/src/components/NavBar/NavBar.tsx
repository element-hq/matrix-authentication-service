// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import styles from "./NavBar.module.css";

const NavBar: React.FC<React.PropsWithChildren> = ({ children }) => (
  <nav className={styles.navBar}>
    <ul className={styles.navBarItems}>{children}</ul>
  </nav>
);

export default NavBar;
