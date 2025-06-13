// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Button } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

type Props = {
  onNext: (() => void) | null;
  onPrev: (() => void) | null;
  // automatically hide the component when there are no onNext/onPrev
  autoHide?: boolean;
  count?: number;
  disabled?: boolean;
};

const PaginationControls: React.FC<Props> = ({
  onNext,
  onPrev,
  autoHide,
  count,
  disabled,
}) => {
  const { t } = useTranslation();

  if (autoHide && !onNext && !onPrev) {
    return null;
  }
  return (
    <div className="grid items-center grid-cols-3 gap-2">
      <Button
        kind="secondary"
        size="sm"
        disabled={disabled || !onPrev}
        onClick={(): void => onPrev?.()}
      >
        {t("common.previous")}
      </Button>
      <div className="text-center">
        {count !== undefined ? (
          <>{t("frontend.pagination_controls.total", { totalCount: count })}</>
        ) : null}
      </div>
      <Button
        kind="secondary"
        size="sm"
        disabled={disabled || !onNext}
        onClick={(): void => onNext?.()}
      >
        {t("common.next")}
      </Button>
    </div>
  );
};

export default PaginationControls;
