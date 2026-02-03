// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import IconDelete from "@vector-im/compound-design-tokens/assets/web/icons/delete";
import {
  Button,
  EditInPlace,
  ErrorMessage,
  Form,
  IconButton,
  Tooltip,
} from "@vector-im/compound-web";
import { parseISO } from "date-fns";
import { type ComponentProps, type ReactNode, useState } from "react";
import { Translation, useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { formatReadableDate } from "../DateTime";
import { Close, Description, Dialog, Title } from "../Dialog";
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
  mutation RenamePasskey($id: ID!, $name: String!) {
    renamePasskey(input: { id: $id, name: $name }) {
      status
    }
  }
`);

const DeleteButton: React.FC<{ disabled?: boolean; onClick?: () => void }> = ({
  disabled,
  onClick,
}) => (
  <Translation>
    {(t): ReactNode => (
      <Tooltip label={t("frontend.account.passkeys.delete_button_title")}>
        <IconButton
          type="button"
          disabled={disabled}
          className="m-2"
          onClick={onClick}
          size="var(--cpd-space-8x)"
        >
          <IconDelete className={styles.userPasskeyDeleteIcon} />
        </IconButton>
      </Tooltip>
    )}
  </Translation>
);

const DeleteButtonWithConfirmation: React.FC<
  ComponentProps<typeof DeleteButton> & { name: string }
> = ({ name, onClick, ...rest }) => {
  const { t } = useTranslation();
  const onConfirm = (): void => {
    onClick?.();
  };

  // NOOP function, otherwise we dont render a cancel button
  const onDeny = (): void => {};

  return (
    <Dialog trigger={<DeleteButton {...rest} />}>
      <Title>
        {t("frontend.account.passkeys.delete_button_confirmation_modal.body")}
      </Title>
      <Description className={styles.passkeyModalBox}>
        <div>{name}</div>
      </Description>
      <div className="flex flex-col gap-4">
        <Close asChild>
          <Button
            kind="primary"
            destructive
            onClick={onConfirm}
            Icon={IconDelete}
          >
            {t(
              "frontend.account.passkeys.delete_button_confirmation_modal.action",
            )}
          </Button>
        </Close>
        <Close asChild>
          <Button kind="tertiary" onClick={onDeny}>
            {t("action.cancel")}
          </Button>
        </Close>
      </div>
    </Dialog>
  );
};

const UserPasskey: React.FC<{
  passkey: FragmentType<typeof FRAGMENT>;
  onRemove: () => void;
}> = ({ passkey, onRemove }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, passkey);
  const [value, setValue] = useState(data.name);
  const queryClient = useQueryClient();

  const removePasskey = useMutation({
    mutationFn: (id: string) =>
      graphqlRequest({ query: REMOVE_PASSKEY_MUTATION, variables: { id } }),
    onSuccess: (_data) => {
      onRemove?.();
      queryClient.invalidateQueries({ queryKey: ["userPasskeys"] });
    },
  });
  const renamePasskey = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      graphqlRequest({
        query: RENAME_PASSKEY_MUTATION,
        variables: { id, name },
      }),
    onSuccess: (data) => {
      if (data.renamePasskey.status !== "RENAMED") {
        return;
      }
      queryClient.invalidateQueries({ queryKey: ["userPasskeys"] });
    },
  });

  const formattedLastUsed = data.lastUsedAt
    ? formatReadableDate(parseISO(data.lastUsedAt), new Date())
    : "";
  const formattedCreated = formatReadableDate(
    parseISO(data.createdAt),
    new Date(),
  );
  const status = renamePasskey.data?.renamePasskey.status ?? null;

  const onRemoveClick = (): void => {
    removePasskey.mutate(data.id);
  };

  const onInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    setValue(e.target.value);
  };
  const onCancel = () => {
    console.log("wee");
    setValue(data.name);
  };
  const handleSubmit = async (
    e: React.FormEvent<HTMLFormElement>,
  ): Promise<void> => {
    e.preventDefault();

    const formData = new FormData(e.currentTarget);
    const name = formData.get("input") as string;

    await renamePasskey.mutateAsync({ id: data.id, name });
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <EditInPlace
          onSave={handleSubmit}
          type="text"
          value={value}
          onInput={onInput}
          onCancel={onCancel}
          serverInvalid={!!status && status !== "RENAMED"}
          className="flex-1"
          label=""
          saveButtonLabel={t("action.save")}
          savingLabel={t("common.saving")}
          savedLabel={t("common.saved")}
          cancelButtonLabel={t("action.cancel")}
        >
          <ErrorMessage match="typeMismatch" forceMatch={status === "INVALID"}>
            {t("frontend.account.passkeys.name_invalid_error")}
          </ErrorMessage>
        </EditInPlace>

        <DeleteButtonWithConfirmation
          name={data.name}
          disabled={removePasskey.isPending}
          onClick={onRemoveClick}
        />
      </div>

      <Form.Root>
        <Form.Field name="">
          <Form.HelpMessage>{data.aaguid.id}</Form.HelpMessage>
          <Form.HelpMessage>
            {data.lastUsedAt
              ? t("frontend.account.passkeys.last_used_message", {
                  date: formattedLastUsed,
                })
              : t("frontend.account.passkeys.never_used_message")}
          </Form.HelpMessage>
          <Form.HelpMessage>
            {t("frontend.account.passkeys.created_at_message", {
              date: formattedCreated,
            })}
          </Form.HelpMessage>
        </Form.Field>
      </Form.Root>
    </div>
  );
};

export default UserPasskey;
