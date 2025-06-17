// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import IconDelete from "@vector-im/compound-design-tokens/assets/web/icons/delete";
import IconEmail from "@vector-im/compound-design-tokens/assets/web/icons/email";
import {
  Button,
  ErrorMessage,
  Form,
  IconButton,
  Tooltip,
} from "@vector-im/compound-web";
import { type ReactNode, useCallback, useState } from "react";
import { Translation, useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { Close, Description, Dialog, Title } from "../Dialog";
import LoadingSpinner from "../LoadingSpinner";
import PasswordConfirmationModal, {
  usePasswordConfirmation,
} from "../PasswordConfirmation";
import styles from "./UserEmail.module.css";

// This component shows a single user email address, with controls to remove it

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_email on UserEmail {
    id
    email
  }
`);

const REMOVE_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation RemoveEmail($id: ID!, $password: String) {
    removeEmail(input: { userEmailId: $id, password: $password }) {
      status

      user {
        id
      }
    }
  }
`);

const DeleteButton: React.FC<{ disabled?: boolean; onClick?: () => void }> = ({
  disabled,
  onClick,
}) => (
  <Translation>
    {(t): ReactNode => (
      <Tooltip label={t("frontend.user_email.delete_button_title")}>
        <IconButton
          type="button"
          disabled={disabled}
          className="m-2"
          onClick={onClick}
          size="var(--cpd-space-8x)"
        >
          <IconDelete className={styles.userEmailDeleteIcon} />
        </IconButton>
      </Tooltip>
    )}
  </Translation>
);

const UserEmail: React.FC<{
  email: FragmentType<typeof FRAGMENT>;
  canRemove?: boolean;
  shouldPromptPassword?: boolean;
  onRemove?: () => void;
}> = ({ email, canRemove, shouldPromptPassword, onRemove }) => {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const data = useFragment(FRAGMENT, email);
  const queryClient = useQueryClient();
  const [promptPassword, passwordConfirmationRef] = usePasswordConfirmation();

  const removeEmail = useMutation({
    mutationFn: ({ id, password }: { id: string; password?: string }) =>
      graphqlRequest({
        query: REMOVE_EMAIL_MUTATION,
        variables: { id, password },
      }),

    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["currentUserGreeting"] });
      queryClient.invalidateQueries({ queryKey: ["userEmails"] });

      // Don't close the modal unless the mutation was successful removed (or not found)
      if (
        data.removeEmail.status !== "NOT_FOUND" &&
        data.removeEmail.status !== "REMOVED"
      ) {
        return;
      }

      onRemove?.();
      setOpen(false);
    },
  });

  const onRemoveClick = useCallback(
    async (_e: React.MouseEvent<HTMLButtonElement>): Promise<void> => {
      let password = undefined;
      if (shouldPromptPassword) {
        password = await promptPassword();
      }
      removeEmail.mutate({ id: data.id, password });
    },
    [data.id, promptPassword, shouldPromptPassword, removeEmail.mutate],
  );

  const onOpenChange = useCallback(
    (open: boolean) => {
      // Don't change the modal state if the mutation is pending
      if (removeEmail.isPending) return;
      removeEmail.reset();
      setOpen(open);
    },
    [removeEmail.isPending, removeEmail.reset],
  );

  const status = removeEmail.data?.removeEmail.status ?? null;

  return (
    <>
      <PasswordConfirmationModal
        title={t(
          "frontend.user_email.delete_button_confirmation_modal.password_confirmation",
        )}
        destructive
        ref={passwordConfirmationRef}
      />
      <Form.Root>
        <Form.Field name="email">
          <Form.Label>{t("frontend.user_email.email")}</Form.Label>

          <div className="flex items-center gap-2">
            <Form.TextControl
              type="email"
              readOnly
              value={data.email}
              className={styles.userEmailField}
            />
            {canRemove && (
              <Dialog
                trigger={<DeleteButton />}
                open={open}
                onOpenChange={onOpenChange}
              >
                <Title>
                  {t(
                    "frontend.user_email.delete_button_confirmation_modal.body",
                  )}
                </Title>
                <Description className={styles.emailModalBox}>
                  <IconEmail />
                  <div>{data.email}</div>
                </Description>

                {status === "INCORRECT_PASSWORD" && (
                  <ErrorMessage>
                    {t(
                      "frontend.user_email.delete_button_confirmation_modal.incorrect_password",
                    )}
                  </ErrorMessage>
                )}

                <div className="flex flex-col gap-4">
                  <Button
                    kind="primary"
                    type="button"
                    destructive
                    onClick={onRemoveClick}
                    disabled={removeEmail.isPending}
                    Icon={removeEmail.isPending ? undefined : IconDelete}
                  >
                    {!!removeEmail.isPending && <LoadingSpinner inline />}
                    {t(
                      "frontend.user_email.delete_button_confirmation_modal.action",
                    )}
                  </Button>
                  <Close asChild>
                    <Button disabled={removeEmail.isPending} kind="tertiary">
                      {t("action.cancel")}
                    </Button>
                  </Close>
                </div>
              </Dialog>
            )}
          </div>
        </Form.Field>
      </Form.Root>
    </>
  );
};

export default UserEmail;
