// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconEdit from "@vector-im/compound-design-tokens/assets/web/icons/edit";
import { Button, Form, IconButton, Tooltip } from "@vector-im/compound-web";
import {
  type ComponentPropsWithoutRef,
  forwardRef,
  useRef,
  useState,
} from "react";
import * as Dialog from "../Dialog";
import LoadingSpinner from "../LoadingSpinner";

import type { UseMutationResult } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";

// This needs to be its own component because else props and refs aren't passed properly in the trigger
const EditButton = forwardRef<
  HTMLButtonElement,
  { label: string } & ComponentPropsWithoutRef<"button">
>(({ label, ...props }, ref) => (
  <Tooltip label={label}>
    <IconButton
      ref={ref}
      type="button"
      size="var(--cpd-space-6x)"
      style={{ marginInline: "var(--cpd-space-2x)" }}
      {...props}
    >
      <IconEdit />
    </IconButton>
  </Tooltip>
));

type Props = {
  mutation: UseMutationResult<unknown, unknown, string, unknown>;
  deviceName: string;
};

const EditSessionName: React.FC<Props> = ({ mutation, deviceName }) => {
  const { t } = useTranslation();
  const fieldRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState(false);

  const onSubmit = async (
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> => {
    event.preventDefault();

    const form = event.currentTarget;
    const formData = new FormData(form);
    const displayName = formData.get("name") as string;
    await mutation.mutateAsync(displayName);
    setOpen(false);
  };
  return (
    <Dialog.Dialog
      trigger={<EditButton label={t("action.edit")} />}
      open={open}
      onOpenChange={(open) => {
        // Reset the form when the dialog is opened or closed
        fieldRef.current?.form?.reset();
        setOpen(open);
      }}
    >
      <Dialog.Title>{t("frontend.session.set_device_name.title")}</Dialog.Title>

      <Form.Root onSubmit={onSubmit}>
        <Form.Field name="name">
          <Form.Label>{t("frontend.session.set_device_name.label")}</Form.Label>

          <Form.TextControl
            type="text"
            required
            defaultValue={deviceName}
            ref={fieldRef}
          />

          <Form.HelpMessage>
            {t("frontend.session.set_device_name.help")}
          </Form.HelpMessage>
        </Form.Field>

        <Form.Submit disabled={mutation.isPending}>
          {mutation.isPending && <LoadingSpinner inline />}
          {t("action.save")}
        </Form.Submit>
      </Form.Root>

      <Dialog.Close asChild>
        <Button kind="tertiary">{t("action.cancel")}</Button>
      </Dialog.Close>
    </Dialog.Dialog>
  );
};

export default EditSessionName;
