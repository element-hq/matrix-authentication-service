// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import cx from "classnames";
import { differenceInSeconds, parseISO } from "date-fns";
import { useTranslation } from "react-i18next";

import { formatDate, formatReadableDate } from "../DateTime";

import styles from "./LastActive.module.css";

// 3 minutes
const ACTIVE_NOW_MAX_AGE = 60 * 3;
/// 90 days
const INACTIVE_MIN_AGE = 60 * 60 * 24 * 90;

const LastActive: React.FC<{
  lastActive: Date | string;
  now?: Date | string;
  className?: string;
}> = ({ lastActive: lastActiveProps, now: nowProps, className }) => {
  const { t } = useTranslation();

  const lastActive =
    typeof lastActiveProps === "string"
      ? parseISO(lastActiveProps)
      : lastActiveProps;

  const now = nowProps
    ? typeof nowProps === "string"
      ? parseISO(nowProps)
      : nowProps
    : new Date();

  const formattedDate = formatDate(lastActive);
  if (differenceInSeconds(now, lastActive) <= ACTIVE_NOW_MAX_AGE) {
    return (
      <span title={formattedDate} className={cx(styles.active, className)}>
        {t("frontend.last_active.active_now")}
      </span>
    );
  }
  if (differenceInSeconds(now, lastActive) > INACTIVE_MIN_AGE) {
    return (
      <span title={formattedDate} className={className}>
        {t("frontend.last_active.inactive_90_days")}
      </span>
    );
  }
  const relativeDate = formatReadableDate(lastActive, now);
  return (
    <span title={formattedDate} className={className}>
      {t("frontend.last_active.active_date", { relativeDate })}
    </span>
  );
};

export default LastActive;
