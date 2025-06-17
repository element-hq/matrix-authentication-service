// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useMutation } from "@tanstack/react-query";
import IconDelete from "@vector-im/compound-design-tokens/assets/web/icons/delete";
import { Alert, Avatar, Button, Form, Text } from "@vector-im/compound-web";
import { useCallback, useEffect, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../gql";
import { graphqlRequest } from "../graphql";
import * as Dialog from "./Dialog";
import LoadingSpinner from "./LoadingSpinner";
import Separator from "./Separator";

export const USER_FRAGMENT = graphql(/* GraphQL */ `
  fragment AccountDeleteButton_user on User {
    username
    hasPassword
    matrix {
      mxid
      displayName
    }
  }
`);

export const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment AccountDeleteButton_siteConfig on SiteConfig {
    passwordLoginEnabled
  }
`);

const MUTATION = graphql(/* GraphQL */ `
  mutation DeactivateUser($hsErase: Boolean!, $password: String) {
    deactivateUser(input: { hsErase: $hsErase, password: $password }) {
      status
    }
  }
`);

type Props = {
  user: FragmentType<typeof USER_FRAGMENT>;
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
};

const UserCard: React.FC<{
  mxid: string;
  displayName?: string | null;
  username: string;
}> = ({ mxid, displayName, username }) => (
  <section className="flex items-center p-4 gap-4 border border-[var(--cpd-color-gray-400)] rounded-xl">
    <Avatar id={mxid} name={displayName || username} size="56px" />
    <div className="flex-1 flex flex-col">
      <Text type="body" weight="semibold" size="lg" className="text-primary">
        {displayName || username}
      </Text>
      <Text type="body" weight="regular" size="md" className="text-secondary">
        {mxid}
      </Text>
    </div>
  </section>
);

const AccountDeleteButton: React.FC<Props> = (props) => {
  const user = useFragment(USER_FRAGMENT, props.user);
  const siteConfig = useFragment(CONFIG_FRAGMENT, props.siteConfig);
  const { t } = useTranslation();
  const mutation = useMutation({
    mutationFn: ({
      password,
      hsErase,
    }: { password: string | null; hsErase: boolean }) =>
      graphqlRequest({
        query: MUTATION,
        variables: { password, hsErase },
      }),
    onSuccess: (data) => {
      if (data.deactivateUser.status === "DEACTIVATED") {
        window.location.reload();
      }
    },
  });

  // Track if the form may be valid or not, so that we show the alert and enable
  // the submit button only when it is
  const [isMaybeValid, setIsMaybeValid] = useState(false);

  // We want to *delay* a little bit the submit button being enabled, so that:
  //   - the user reads the alert
  //   - *if the password manager autofills the password*, we ignore any auto-submitting of the form
  const [allowSubmitting, setAllowSubmitting] = useState(false);

  useEffect(() => {
    // If the value of isMaybeValid switches to true, we want to flip
    // 'allowSubmitting' to true a little bit later
    if (isMaybeValid) {
      const timer = setTimeout(() => {
        setAllowSubmitting(true);
      }, 500);
      return () => clearTimeout(timer);
    }

    // If it switches to false, we want to flip 'allowSubmitting' to false
    // immediately
    setAllowSubmitting(false);
  }, [isMaybeValid]);

  const onPasswordChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      // We don't know if the password is correct, so we consider the form as
      // valid if the field is not empty
      setIsMaybeValid(e.currentTarget.value !== "");
    },
    [],
  );

  const onMxidChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setIsMaybeValid(e.currentTarget.value === user.matrix.mxid);
    },
    [user.matrix.mxid],
  );

  const onSubmit = useCallback(
    (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      if (!allowSubmitting) return;

      const data = new FormData(e.currentTarget);
      const password = data.get("password");
      if (password !== null && typeof password !== "string") throw new Error();
      const hsErase = data.get("hs-erase") === "on";

      mutation.mutate({ password, hsErase });
    },
    [mutation.mutate, allowSubmitting],
  );

  const incorrectPassword =
    mutation.data?.deactivateUser.status === "INCORRECT_PASSWORD";

  // We still consider the form as submitted if the mutation is pending, or if
  // the mutation has returned a success, so that we continue showing the
  // loading spinner during the page reload
  const isSubmitting =
    mutation.isPending ||
    mutation.data?.deactivateUser.status === "DEACTIVATED";

  const shouldPromptPassword =
    user.hasPassword && siteConfig.passwordLoginEnabled;

  return (
    <Dialog.Dialog
      trigger={
        <Button
          kind="tertiary"
          destructive
          size="sm"
          className="self-center"
          Icon={IconDelete}
        >
          {t("frontend.account.delete_account.button")}
        </Button>
      }
    >
      <Dialog.Title>
        {t("frontend.account.delete_account.dialog_title")}
      </Dialog.Title>

      <Dialog.Description className="flex flex-col gap-4">
        <Trans
          t={t}
          i18nKey="frontend.account.delete_account.dialog_description"
          components={{
            text: <Text type="body" weight="regular" size="md" />,
            list: <ul className="list-disc list-outside pl-6" />,
            item: <Text as="li" type="body" weight="regular" size="md" />,
            profile: (
              <UserCard
                mxid={user.matrix.mxid}
                username={user.username}
                displayName={user.matrix.displayName}
              />
            ),
          }}
        />
      </Dialog.Description>

      <Form.Root onSubmit={onSubmit}>
        <Form.InlineField control={<Form.CheckboxControl />} name="hs-erase">
          <Form.Label>
            {t("frontend.account.delete_account.erase_checkbox_label")}
          </Form.Label>
        </Form.InlineField>

        <Separator className="my-1" />

        {shouldPromptPassword ? (
          <Form.Field name="password" serverInvalid={incorrectPassword}>
            <Form.Label>
              {t("frontend.account.delete_account.password_label")}
            </Form.Label>

            <Form.PasswordControl
              autoComplete="current-password"
              required
              onInput={onPasswordChange}
            />

            <Form.ErrorMessage match="valueMissing">
              {t("frontend.errors.field_required")}
            </Form.ErrorMessage>

            {incorrectPassword && (
              <Form.ErrorMessage>
                {t("frontend.account.delete_account.incorrect_password")}
              </Form.ErrorMessage>
            )}
          </Form.Field>
        ) : (
          <Form.Field name="mxid">
            <Form.Label>
              {t("frontend.account.delete_account.mxid_label", {
                mxid: user.matrix.mxid,
              })}
            </Form.Label>

            <Form.TextControl
              required
              placeholder={user.matrix.mxid}
              onInput={onMxidChange}
            />

            <Form.ErrorMessage match="valueMissing">
              {t("frontend.errors.field_required")}
            </Form.ErrorMessage>

            <Form.ErrorMessage match={(value) => value !== user.matrix.mxid}>
              {t("frontend.account.delete_account.mxid_mismatch")}
            </Form.ErrorMessage>
          </Form.Field>
        )}

        {isMaybeValid && (
          <Alert
            type="critical"
            title={t("frontend.account.delete_account.alert_title")}
          >
            {t("frontend.account.delete_account.alert_description")}
          </Alert>
        )}

        <Button
          type="submit"
          kind="primary"
          destructive
          disabled={!allowSubmitting || isSubmitting}
          Icon={isSubmitting ? undefined : IconDelete}
        >
          {isSubmitting && <LoadingSpinner inline />}
          {t("frontend.account.delete_account.button")}
        </Button>
      </Form.Root>

      <Dialog.Close asChild>
        <Button kind="tertiary">{t("action.cancel")}</Button>
      </Dialog.Close>
    </Dialog.Dialog>
  );
};

export default AccountDeleteButton;
