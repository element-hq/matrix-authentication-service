// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Link } from "@tanstack/react-router";
import { Form } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { type FragmentType, graphql, useFragment } from "../../gql";

import styles from "./AccountManagementPasswordPreview.module.css";

export const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment PasswordChange_siteConfig on SiteConfig {
    passwordChangeAllowed
  }
`);

export default function AccountManagementPasswordPreview({
  siteConfig,
}: {
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
}): React.ReactElement {
  const { t } = useTranslation();
  const { passwordChangeAllowed } = useFragment(CONFIG_FRAGMENT, siteConfig);

  return (
    <Form.Root>
      <Form.Field name="password_preview">
        <Form.Label>{t("frontend.account.password.label")}</Form.Label>

        <Form.TextControl
          type="password"
          readOnly
          value="this looks like a password"
        />

        <Form.HelpMessage>
          {passwordChangeAllowed && (
            <Link to="/password/change" className={styles.link}>
              {t("frontend.account.password.change")}
            </Link>
          )}

          {!passwordChangeAllowed &&
            t("frontend.account.password.change_disabled")}
        </Form.HelpMessage>
      </Form.Field>
    </Form.Root>
  );
}
