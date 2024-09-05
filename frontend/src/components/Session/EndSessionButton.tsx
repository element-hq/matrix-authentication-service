// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconSignOut from "@vector-im/compound-design-tokens/assets/web/icons/sign-out";
import { Button } from "@vector-im/compound-web";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import * as Dialog from "../Dialog";
import LoadingSpinner from "../LoadingSpinner/LoadingSpinner";

/**
 * Generic end session button
 * Handles loading state while endSession is in progress
 */
const EndSessionButton: React.FC<
  React.PropsWithChildren<{ endSession: () => Promise<void> }>
> = ({ children, endSession }) => {
  const [inProgress, setInProgress] = useState(false);
  const [open, setOpen] = useState(false);
  const { t } = useTranslation();

  const onConfirm = async (
    e: React.MouseEvent<HTMLButtonElement>,
  ): Promise<void> => {
    e.preventDefault();

    setInProgress(true);
    try {
      await endSession();
      setOpen(false);
    } catch (error) {
      console.error("Failed to end session", error);
    }
    setInProgress(false);
  };

  return (
    <Dialog.Dialog
      open={open}
      onOpenChange={setOpen}
      trigger={
        <Button kind="secondary" destructive size="sm" Icon={IconSignOut}>
          {t("frontend.end_session_button.text")}
        </Button>
      }
    >
      <Dialog.Title>
        {t("frontend.end_session_button.confirmation_modal_title")}
      </Dialog.Title>

      {children && <Dialog.Description>{children}</Dialog.Description>}

      <Button
        type="button"
        kind="primary"
        destructive
        onClick={onConfirm}
        disabled={inProgress}
        Icon={inProgress ? undefined : IconSignOut}
      >
        {inProgress && <LoadingSpinner inline />}
        {t("frontend.end_session_button.text")}
      </Button>

      <Dialog.Close asChild>
        <Button kind="tertiary">{t("action.cancel")}</Button>
      </Dialog.Close>
    </Dialog.Dialog>
  );
};

export default EndSessionButton;
