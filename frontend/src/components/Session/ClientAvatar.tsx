// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { CSSProperties } from "react";

import styles from "./ClientAvatar.module.css";

/**
 * Render a client logo avatar when logoUri is truthy
 * Otherwise return null
 */
const ClientAvatar: React.FC<{
  name: string;
  logoUri?: string;
  size: string;
}> = ({ name, logoUri, size }) => {
  // compound's lazy loading for avatars does not allow CORS requests
  // so use our own avatar styled img
  if (logoUri) {
    return (
      <img
        className={styles.avatar}
        src={logoUri}
        alt={name}
        referrerPolicy="no-referrer"
        style={
          {
            "--mas-avatar-size": size,
          } as CSSProperties
        }
      />
    );
  }
  return null;
};

export default ClientAvatar;
