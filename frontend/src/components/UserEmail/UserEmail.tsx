// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import IconDelete from "@vector-im/compound-design-tokens/assets/web/icons/delete";
import IconEmail from "@vector-im/compound-design-tokens/assets/web/icons/email";
import { Button, Form, IconButton, Tooltip } from "@vector-im/compound-web";
import type { ComponentProps, ReactNode } from "react";
import { Translation, useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { Close, Description, Dialog, Title } from "../Dialog";
import { Link } from "../Link";
import styles from "./UserEmail.module.css";

// This component shows a single user email address, with controls to verify it,
// resend the verification email, remove it, and set it as the primary email address.

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_email on UserEmail {
    id
    email
    confirmedAt
  }
`);

export const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_siteConfig on SiteConfig {
    emailChangeAllowed
  }
`);

const REMOVE_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation RemoveEmail($id: ID!) {
    removeEmail(input: { userEmailId: $id }) {
      status

      user {
        id
      }
    }
  }
`);

const SET_PRIMARY_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation SetPrimaryEmail($id: ID!) {
    setPrimaryEmail(input: { userEmailId: $id }) {
      status
      user {
        id
        primaryEmail {
          id
        }
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

const DeleteButtonWithConfirmation: React.FC<
  ComponentProps<typeof DeleteButton> & { email: string }
> = ({ email, onClick, ...rest }) => {
  const { t } = useTranslation();
  const onConfirm = (): void => {
    onClick?.();
  };

  // NOOP function, otherwise we dont render a cancel button
  const onDeny = (): void => {};

  return (
    <Dialog trigger={<DeleteButton {...rest} />}>
      <Title>
        {t("frontend.user_email.delete_button_confirmation_modal.body")}
      </Title>
      <Description className={styles.emailModalBox}>
        <IconEmail />
        <div>{email}</div>
      </Description>
      <div className="flex flex-col gap-4">
        <Close asChild>
          <Button
            kind="primary"
            destructive
            onClick={onConfirm}
            Icon={IconDelete}
          >
            {t("frontend.user_email.delete_button_confirmation_modal.action")}
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

const UserEmail: React.FC<{
  email: FragmentType<typeof FRAGMENT>;
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
  onRemove?: () => void;
  isPrimary?: boolean;
}> = ({ email, siteConfig, isPrimary, onRemove }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, email);
  const { emailChangeAllowed } = useFragment(CONFIG_FRAGMENT, siteConfig);
  const queryClient = useQueryClient();

  const setPrimary = useMutation({
    mutationFn: (id: string) =>
      graphqlRequest({ query: SET_PRIMARY_EMAIL_MUTATION, variables: { id } }),
    onSuccess: (_data) => {
      queryClient.invalidateQueries({ queryKey: ["currentUserGreeting"] });
      queryClient.invalidateQueries({ queryKey: ["userEmails"] });
    },
  });

  const removeEmail = useMutation({
    mutationFn: (id: string) =>
      graphqlRequest({ query: REMOVE_EMAIL_MUTATION, variables: { id } }),
    onSuccess: (_data) => {
      onRemove?.();
      queryClient.invalidateQueries({ queryKey: ["currentUserGreeting"] });
      queryClient.invalidateQueries({ queryKey: ["userEmails"] });
    },
  });

  const onRemoveClick = (): void => {
    removeEmail.mutate(data.id);
  };

  const onSetPrimaryClick = (): void => {
    setPrimary.mutate(data.id);
  };

  return (
    <Form.Root>
      <Form.Field name="email">
        <Form.Label>
          {isPrimary
            ? t("frontend.user_email.primary_email")
            : t("frontend.user_email.email")}
        </Form.Label>

        <div className="flex items-center gap-2">
          <Form.TextControl
            type="email"
            readOnly
            value={data.email}
            className={styles.userEmailField}
          />
          {!isPrimary && emailChangeAllowed && (
            <DeleteButtonWithConfirmation
              email={data.email}
              disabled={removeEmail.isPending}
              onClick={onRemoveClick}
            />
          )}
        </div>

        {isPrimary && emailChangeAllowed && (
          <Form.HelpMessage>
            {t("frontend.user_email.cant_delete_primary")}
          </Form.HelpMessage>
        )}

        {data.confirmedAt && !isPrimary && emailChangeAllowed && (
          <Form.HelpMessage>
            <button
              type="button"
              className={styles.link}
              disabled={setPrimary.isPending}
              onClick={onSetPrimaryClick}
            >
              {t("frontend.user_email.make_primary_button")}
            </button>
          </Form.HelpMessage>
        )}

        {!data.confirmedAt && (
          <Form.ErrorMessage>
            {t("frontend.user_email.not_verified")} |{" "}
            <Link to="/emails/$id/verify" params={{ id: data.id }}>
              {t("frontend.user_email.retry_button")}
            </Link>
          </Form.ErrorMessage>
        )}
      </Form.Field>
    </Form.Root>
  );
};

export default UserEmail;
