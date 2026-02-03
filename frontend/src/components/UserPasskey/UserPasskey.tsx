// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import IconDelete from "@vector-im/compound-design-tokens/assets/web/icons/delete";
import { Button, IconButton, Text } from "@vector-im/compound-web";
import { parseISO } from "date-fns";
import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { formatReadableDate } from "../DateTime";
import * as Dialog from "../Dialog";
import LoadingSpinner from "../LoadingSpinner";
import styles from "./UserPasskey.module.css";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserPasskey_passkey on UserPasskey {
    id
    name
    lastUsedAt
    createdAt
    aaguid {
      id
      name
    }
  }
`);

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

const DeleteButtonWithConfirmation: React.FC<{
  name: string;
  id: string;
  onRemove: () => void;
}> = ({ name, id, onRemove }) => {
  const { t } = useTranslation();
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
      mutate(id);
    },
    [mutate, id],
  );

  return (
    <Dialog.Dialog
      onOpenChange={setOpen}
      open={open}
      trigger={
        <IconButton
          tooltip={t("frontend.account.passkeys.delete_button_title")}
          type="button"
          className="m-2"
          size="var(--cpd-space-8x)"
        >
          <IconDelete className={styles.userPasskeyDeleteIcon} />
        </IconButton>
      }
    >
      <Dialog.Title>
        {t("frontend.account.passkeys.delete_button_confirmation_modal.body")}
      </Dialog.Title>
      <Dialog.Description className={styles.passkeyModalBox}>
        <div>{name}</div>
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
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, passkey);
  const queryClient = useQueryClient();

  // TODO
  const _renamePasskey = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      graphqlRequest({
        query: RENAME_PASSKEY_MUTATION,
        variables: { id, name },
      }),
    async onSuccess(data) {
      if (data.renamePasskey.status !== "RENAMED") {
        return;
      }
      await queryClient.invalidateQueries({ queryKey: ["userPasskeys"] });
    },
  });

  const formattedLastUsed = data.lastUsedAt
    ? formatReadableDate(parseISO(data.lastUsedAt), new Date())
    : "";
  const formattedCreated = formatReadableDate(
    parseISO(data.createdAt),
    new Date(),
  );

  const name = data.name ?? data.aaguid.name ?? data.aaguid.id;

  return (
    <div className="flex items-center gap-2">
      <div className="flex flex-1 flex-col gap-1">
        <Text weight="semibold">{name}</Text>
        <Text size="sm" weight="medium" className="cpd-text-secondary">
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

      <DeleteButtonWithConfirmation
        name={name}
        id={data.id}
        onRemove={onRemove}
      />
    </div>
  );
};

export default UserPasskey;
