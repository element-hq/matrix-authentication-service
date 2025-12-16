// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { UseMutationResult } from "@tanstack/react-query";
import IconDelete from "@vector-im/compound-design-tokens/assets/web/icons/delete";
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
  React.PropsWithChildren<{
    mutation: UseMutationResult<unknown, unknown, void>;
    size: "sm" | "lg";
  }>
> = ({ children, mutation, size }) => {
  const [open, setOpen] = useState(false);
  const { t } = useTranslation();

  const onConfirm = (e: React.MouseEvent<HTMLButtonElement>): void => {
    e.preventDefault();
    mutation.mutate(void 0, { onSuccess: () => setOpen(false) });
  };

  return (
    <Dialog.Dialog
      open={open}
      onOpenChange={setOpen}
      trigger={
        <Button kind="secondary" destructive size={size} Icon={IconDelete}>
          {t("frontend.end_session_button.text")}
        </Button>
      }
    >
      <Dialog.Title>
        {t("frontend.end_session_button.confirmation_modal_title")}
      </Dialog.Title>

      {children && <Dialog.Description asChild>{children}</Dialog.Description>}

      <Button
        type="button"
        kind="primary"
        destructive
        onClick={onConfirm}
        disabled={mutation.isPending}
        Icon={mutation.isPending ? undefined : IconDelete}
      >
        {mutation.isPending && <LoadingSpinner inline />}
        {t("frontend.end_session_button.text")}
      </Button>

      <Dialog.Close asChild>
        <Button kind="tertiary">{t("action.cancel")}</Button>
      </Dialog.Close>
    </Dialog.Dialog>
  );
};

export default EndSessionButton;
