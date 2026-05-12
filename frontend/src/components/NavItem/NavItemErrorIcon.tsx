// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import IconErrorSolid from "@vector-im/compound-design-tokens/assets/web/icons/error-solid";

import styles from "./NavItem.module.css";

const NavItemErrorIcon: React.FC = (_props) => {
  return <IconErrorSolid className={styles.navBarErrorIcon} />;
};

export default NavItemErrorIcon;
