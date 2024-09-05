// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { Alert } from "@vector-im/compound-web";
import { ReactNode } from "react";
import { Translation } from "react-i18next";

const NotLoggedIn: React.FC = () => (
  <Translation>
    {(t): ReactNode => (
      <Alert type="critical" title={t("frontend.not_logged_in_alert")} />
    )}
  </Translation>
);

export default NotLoggedIn;
