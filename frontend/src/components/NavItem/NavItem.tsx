// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Link } from "@tanstack/react-router";

import styles from "./NavItem.module.css";

const NavItem: React.FC<React.ComponentProps<typeof Link>> = (props) => {
  return (
    <li className={styles.navTab}>
      <Link
        className={styles.navItem}
        activeProps={{ "aria-current": "page" }}
        {...props}
      />
    </li>
  );
};

export default NavItem;
