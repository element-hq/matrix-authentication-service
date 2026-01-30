// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Button, Form } from "@vector-im/compound-web";
import type React from "react";
import { useCallback, useImperativeHandle, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Dialog from "./Dialog";

type ModalRef = {
  prompt: () => Promise<string>;
};

type Props = {
  title: string;
  destructive?: boolean;
  ref: React.Ref<ModalRef>;
};

/**
 * A hook that returns a function that prompts the user to enter a password.
 * The returned function returns a promise that resolves to the password, and
 * throws an error if the user cancels the prompt.
 *
 * It also returns a ref that must be passed to a mounted Modal component.
 */
export const usePasswordConfirmation = (): [
  () => Promise<string>,
  React.RefObject<ModalRef>,
] => {
  const ref = useRef<ModalRef>({
    prompt: () => {
      throw new Error("PasswordConfirmationModal is not mounted!");
    },
  });

  const prompt = useCallback(() => ref.current.prompt(), []);

  return [prompt, ref] as const;
};

const PasswordConfirmationModal: React.FC<Props> = ({
  title,
  destructive,
  ref,
}) => {
  const [open, setOpen] = useState(false);
  const { t } = useTranslation();
  const resolversRef = useRef<PromiseWithResolvers<string>>(null);

  useImperativeHandle(ref, () => ({
    prompt: () => {
      setOpen(true);
      if (resolversRef.current === null) {
        resolversRef.current = Promise.withResolvers();
      }
      return resolversRef.current.promise;
    },
  }));

  const onOpenChange = useCallback((open: boolean) => {
    setOpen(open);
    if (!open) {
      resolversRef.current?.reject(new Error("User cancelled password prompt"));
      resolversRef.current = null;
    }
  }, []);

  const onSubmit = useCallback((e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const password = data.get("password");
    if (typeof password !== "string") {
      throw new Error(); // This should never happen
    }
    resolversRef.current?.resolve(password);
    resolversRef.current = null;
    setOpen(false);
  }, []);

  return (
    <Dialog.Dialog open={open} onOpenChange={onOpenChange}>
      <Dialog.Title>{title}</Dialog.Title>

      <Dialog.Description asChild>
        <Form.Root onSubmit={onSubmit}>
          <Form.Field name="password">
            <Form.Label>{t("common.password")}</Form.Label>
            <Form.PasswordControl autoFocus autoComplete="current-password" />
          </Form.Field>

          <Button type="submit" kind="primary" destructive={destructive}>
            {t("action.confirm")}
          </Button>
        </Form.Root>
      </Dialog.Description>

      <Dialog.Close asChild>
        <Button kind="tertiary">{t("action.cancel")}</Button>
      </Dialog.Close>
    </Dialog.Dialog>
  );
};

export default PasswordConfirmationModal;
