// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import IconErrorSolid from "@vector-im/compound-design-tokens/assets/web/icons/error-solid";
import { Button } from "@vector-im/compound-web";
import { useState } from "react";
import { Translation } from "react-i18next";
import styles from "./GenericError.module.css";
import PageHeading from "./PageHeading";

const GenericError: React.FC<{ error: unknown; dontSuspend?: boolean }> = ({
  error,
  dontSuspend,
}) => {
  const [open, setOpen] = useState(false);
  return (
    <Translation useSuspense={!dontSuspend}>
      {(t) => (
        <div className="flex flex-col gap-6">
          <PageHeading
            invalid
            Icon={IconErrorSolid}
            title={t("frontend.error.title", {
              defaultValue: "Something went wrong",
            })}
            subtitle={t("frontend.error.subtitle", {
              defaultValue: "An unexpected error occured. Please try again.",
            })}
          />
          <Button kind="tertiary" onClick={() => setOpen(!open)}>
            {open
              ? t("frontend.error.hideDetails", {
                  defaultValue: "Hide details",
                })
              : t("frontend.error.showDetails", {
                  defaultValue: "Show details",
                })}
          </Button>
          {open && (
            <pre className={styles.details}>
              <code>{String(error)}</code>
            </pre>
          )}
        </div>
      )}
    </Translation>
  );
};

export default GenericError;
