// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import styles from "./FieldMessageSlot.module.css";

/**
 * Holds a form field's messages, keeping the room for one even when none is
 * shown, for fields which show a message as they lose focus: the layout would
 * otherwise shift under the click which moved the focus away.
 */
const FieldMessageSlot: React.FC<React.PropsWithChildren> = ({ children }) => (
  <div className={styles.slot}>{children}</div>
);

export default FieldMessageSlot;
