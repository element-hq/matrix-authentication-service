// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { H5, Text } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { type FragmentType, graphql, useFragment } from "../../gql";
import { Link } from "../Link";

import styles from "./BrowserSessionsOverview.module.css";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSessionsOverview_user on User {
    id

    browserSessions(first: 0, state: ACTIVE) {
      totalCount
    }
  }
`);

const BrowserSessionsOverview: React.FC<{
  user: FragmentType<typeof FRAGMENT>;
}> = ({ user }) => {
  const data = useFragment(FRAGMENT, user);
  const { t } = useTranslation();

  return (
    <div className={styles.browserSessionsOverview}>
      <div className="flex flex-1 flex-col">
        <H5>{t("frontend.browser_sessions_overview.heading")}</H5>
        <Text>
          {t("frontend.browser_sessions_overview.body", {
            count: data.browserSessions.totalCount,
          })}
        </Text>
      </div>
      <Link to="/sessions/browsers">
        {t("frontend.browser_sessions_overview.view_all_button")}
      </Link>
    </div>
  );
};

export default BrowserSessionsOverview;
