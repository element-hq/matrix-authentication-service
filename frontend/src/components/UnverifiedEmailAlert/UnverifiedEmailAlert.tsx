// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { Alert } from "@vector-im/compound-web";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { type FragmentType, graphql, useFragment } from "../../gql";
import { Link } from "../Link";

import styles from "./UnverifiedEmailAlert.module.css";

export const UNVERIFIED_EMAILS_FRAGMENT = graphql(/* GraphQL */ `
  fragment UnverifiedEmailAlert_user on User {
    unverifiedEmails: emails(first: 0, state: PENDING) {
      totalCount
    }
  }
`);

const UnverifiedEmailAlert: React.FC<{
  user?: FragmentType<typeof UNVERIFIED_EMAILS_FRAGMENT>;
}> = ({ user }) => {
  const data = useFragment(UNVERIFIED_EMAILS_FRAGMENT, user);
  const [dismiss, setDismiss] = useState(false);
  const { t } = useTranslation();
  const currentCount = useRef<number>();

  const doDismiss = (): void => setDismiss(true);

  useEffect(() => {
    if (currentCount.current !== data?.unverifiedEmails?.totalCount) {
      currentCount.current = data?.unverifiedEmails?.totalCount;
      setDismiss(false);
    }
  }, [data]);

  if (!data?.unverifiedEmails?.totalCount || dismiss) {
    return null;
  }

  return (
    <Alert
      type="critical"
      title={t("frontend.unverified_email_alert.title")}
      onClose={doDismiss}
      className={styles.alert}
    >
      {t("frontend.unverified_email_alert.text", {
        count: data.unverifiedEmails.totalCount,
      })}{" "}
      <Link to="/" hash="emails">
        {t("frontend.unverified_email_alert.button")}
      </Link>
    </Alert>
  );
};

export default UnverifiedEmailAlert;
