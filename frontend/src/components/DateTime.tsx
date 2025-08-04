// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import {
  differenceInHours,
  formatISO,
  intlFormat,
  intlFormatDistance,
  parseISO,
} from "date-fns";

type Props = {
  className?: string;
  datetime: Date | string;
  now?: Date;
};

export const formatDate = (datetime: Date): string =>
  intlFormat(datetime, {
    year: "numeric",
    month: "short",
    day: "numeric",
    weekday: "short",
    hour: "numeric",
    minute: "numeric",
  });

/**
 * Formats a datetime
 * Uses distance when less than an hour ago
 * Else internationalised `Fri, 21 Jul 2023, 16:14`
 */
export const formatReadableDate = (datetime: Date, now: Date): string =>
  Math.abs(differenceInHours(now, datetime, { roundingMethod: "round" })) > 1
    ? formatDate(datetime)
    : intlFormatDistance(datetime, now);

const DateTime: React.FC<Props> = ({
  datetime: datetimeProps,
  now: nowProps,
  className,
}) => {
  const datetime =
    typeof datetimeProps === "string" ? parseISO(datetimeProps) : datetimeProps;
  const now = nowProps || new Date();
  const text = formatReadableDate(datetime, now);

  return (
    <time className={className} dateTime={formatISO(datetime)}>
      {text}
    </time>
  );
};

export default DateTime;
