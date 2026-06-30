// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation } from "@tanstack/react-query";
import IconDelete from "@vector-im/compound-design-tokens/assets/web/icons/delete";
import IconEdit from "@vector-im/compound-design-tokens/assets/web/icons/edit";
import { Button, Form, Text } from "@vector-im/compound-web";
import { parseISO } from "date-fns";
import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { formatReadableDate } from "../DateTime";
import * as Dialog from "../Dialog";
import LoadingSpinner from "../LoadingSpinner";

// Single fragment containing all fields needed by all components
const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserPasskey_passkey on UserPasskey {
    id
    name
    lastUsedAt
    createdAt
    transports
    aaguid {
      name
    }
  }
`);

/**
 * Hook to compute the display name for a passkey.
 * Priority: user-set name → AAGUID name → transport fallback → generic
 */
const usePasskeyDisplayName = (
  passkey: FragmentType<typeof FRAGMENT>,
): string => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, passkey);

  if (data.name) return data.name;
  if (data.aaguid?.name) return data.aaguid.name;

  if (data.transports.includes("INTERNAL"))
    return t("frontend.account.passkeys.fallback.internal");

  if (data.transports.includes("USB"))
    return t("frontend.account.passkeys.fallback.usb");

  if (data.transports.includes("NFC"))
    return t("frontend.account.passkeys.fallback.nfc");

  if (data.transports.includes("BLE"))
    return t("frontend.account.passkeys.fallback.ble");

  if (data.transports.includes("HYBRID"))
    return t("frontend.account.passkeys.fallback.hybrid");

  if (data.transports.includes("SMART_CARD"))
    return t("frontend.account.passkeys.fallback.smartcard");

  return t("frontend.account.passkeys.fallback.generic");
};

/**
 * Displays passkey information: name, last used date, and creation date.
 * Used in the main list and in modals.
 */
const PasskeyInfo: React.FC<{ passkey: FragmentType<typeof FRAGMENT> }> = ({
  passkey,
}) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, passkey);
  const displayName = usePasskeyDisplayName(passkey);

  const formattedLastUsed = data.lastUsedAt
    ? formatReadableDate(parseISO(data.lastUsedAt), new Date())
    : "";
  const formattedCreated = formatReadableDate(
    parseISO(data.createdAt),
    new Date(),
  );

  return (
    <div className="flex flex-col gap-1">
      <Text weight="semibold">{displayName}</Text>
      <Text size="sm" weight="medium" className="text-secondary">
        {data.lastUsedAt
          ? t("frontend.account.passkeys.last_used_message", {
              date: formattedLastUsed,
            })
          : t("frontend.account.passkeys.never_used_message")}
        {" • "}
        {t("frontend.account.passkeys.created_at_message", {
          date: formattedCreated,
        })}
      </Text>
    </div>
  );
};

const REMOVE_PASSKEY_MUTATION = graphql(/* GraphQL */ `
  mutation RemovePasskey($id: ID!) {
    removePasskey(input: { id: $id }) {
      status
    }
  }
`);

const RENAME_PASSKEY_MUTATION = graphql(/* GraphQL */ `
  mutation RenamePasskey($id: ID!, $name: String) {
    renamePasskey(input: { id: $id, name: $name }) {
      status
    }
  }
`);

const EditButtonWithModal: React.FC<{
  passkey: FragmentType<typeof FRAGMENT>;
}> = ({ passkey }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, passkey);
  const [open, setOpen] = useState(false);
  const fieldRef = useRef<HTMLInputElement>(null);

  const { mutate, isPending } = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string | null }) =>
      graphqlRequest({
        query: RENAME_PASSKEY_MUTATION,
        variables: { id, name },
      }),
    async onSuccess(responseData, _variables, _onMutateResult, { client }) {
      if (responseData.renamePasskey.status === "RENAMED") {
        await client.invalidateQueries({ queryKey: ["userPasskeys"] });
        setOpen(false);
      }
    },
  });

  const onSubmit = useCallback(
    (event: React.FormEvent<HTMLFormElement>): void => {
      event.preventDefault();
      const formData = new FormData(event.currentTarget);
      const newName = (formData.get("name") as string) || null;
      mutate({ id: data.id, name: newName });
    },
    [mutate, data.id],
  );

  return (
    <Dialog.Dialog
      trigger={<Button Icon={IconEdit} iconOnly kind="tertiary" />}
      open={open}
      onOpenChange={(isOpen) => {
        fieldRef.current?.form?.reset();
        setOpen(isOpen);
      }}
    >
      <Dialog.Title>
        {t("frontend.account.passkeys.edit_modal.title")}
      </Dialog.Title>

      <Dialog.Description className="p-2 border border-[var(--cpd-color-gray-400)]">
        <PasskeyInfo passkey={passkey} />
      </Dialog.Description>

      <Form.Root onSubmit={onSubmit}>
        <Form.Field name="name">
          <Form.Label>
            {t("frontend.account.passkeys.edit_modal.name_label")}
          </Form.Label>
          <Form.TextControl
            type="text"
            defaultValue={data.name ?? ""}
            ref={fieldRef}
          />
        </Form.Field>

        <Form.Submit disabled={isPending}>
          {isPending && <LoadingSpinner inline />}
          {t("action.save")}
        </Form.Submit>
        <Dialog.Close asChild>
          <Button kind="tertiary">{t("action.cancel")}</Button>
        </Dialog.Close>
      </Form.Root>
    </Dialog.Dialog>
  );
};

const DeleteButtonWithConfirmation: React.FC<{
  passkey: FragmentType<typeof FRAGMENT>;
  onRemove: () => void;
}> = ({ passkey, onRemove }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, passkey);
  const [open, setOpen] = useState(false);

  const { mutate, isPending } = useMutation({
    mutationFn: (id: string) =>
      graphqlRequest({ query: REMOVE_PASSKEY_MUTATION, variables: { id } }),
    async onSuccess(_data, _variables, _onMutateResult, { client }) {
      await client.invalidateQueries({ queryKey: ["userPasskeys"] });
      setOpen(false);
      onRemove();
    },
  });

  const onDeleteClick = useCallback(
    (event: React.MouseEvent<HTMLButtonElement>): void => {
      event.preventDefault();
      mutate(data.id);
    },
    [mutate, data.id],
  );

  return (
    <Dialog.Dialog
      onOpenChange={setOpen}
      open={open}
      trigger={
        <Button Icon={IconDelete} iconOnly kind="tertiary" destructive />
      }
    >
      <Dialog.Title>
        {t("frontend.account.passkeys.delete_button_confirmation_modal.body")}
      </Dialog.Title>
      <Dialog.Description className="p-2 border border-[var(--cpd-color-gray-400)]">
        <PasskeyInfo passkey={passkey} />
      </Dialog.Description>
      <div className="flex flex-col gap-4">
        <Button
          kind="primary"
          destructive
          disabled={isPending}
          Icon={isPending ? undefined : IconDelete}
          onClick={onDeleteClick}
        >
          {isPending && <LoadingSpinner inline />}
          {t(
            "frontend.account.passkeys.delete_button_confirmation_modal.action",
          )}
        </Button>
        <Dialog.Close asChild>
          <Button kind="tertiary">{t("action.cancel")}</Button>
        </Dialog.Close>
      </div>
    </Dialog.Dialog>
  );
};

const UserPasskey: React.FC<{
  passkey: FragmentType<typeof FRAGMENT>;
  onRemove: () => void;
}> = ({ passkey, onRemove }) => {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1">
        <PasskeyInfo passkey={passkey} />
      </div>
      <EditButtonWithModal passkey={passkey} />
      <DeleteButtonWithConfirmation passkey={passkey} onRemove={onRemove} />
    </div>
  );
};

export default UserPasskey;
