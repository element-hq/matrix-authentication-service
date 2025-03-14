// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  EditInPlace,
  ErrorMessage,
  HelpMessage,
} from "@vector-im/compound-web";
import { useCallback } from "react";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import PasswordConfirmationModal, {
  usePasswordConfirmation,
} from "../PasswordConfirmation";

export const USER_FRAGMENT = graphql(/* GraphQL */ `
  fragment AddEmailForm_user on User {
    hasPassword
  }
`);

export const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment AddEmailForm_siteConfig on SiteConfig {
    passwordLoginEnabled
  }
`);

const ADD_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation AddEmail($email: String!, $password: String, $language: String!) {
    startEmailAuthentication(input: {
      email: $email,
      password: $password,
      language: $language
    }) {
      status
      violations
      authentication {
        id
      }
    }
  }
`);

const AddEmailForm: React.FC<{
  onAdd: (id: string) => Promise<void>;
  user: FragmentType<typeof USER_FRAGMENT>;
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
}> = ({ user, siteConfig, onAdd }) => {
  const { hasPassword } = useFragment(USER_FRAGMENT, user);
  const { passwordLoginEnabled } = useFragment(CONFIG_FRAGMENT, siteConfig);

  const shouldPromptPassword = hasPassword && passwordLoginEnabled;

  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [promptPassword, passwordConfirmationRef] = usePasswordConfirmation();
  const addEmail = useMutation({
    mutationFn: ({
      email,
      password,
      language,
    }: { email: string; password?: string; language: string }) =>
      graphqlRequest({
        query: ADD_EMAIL_MUTATION,
        variables: { email, password, language },
      }),
    onSuccess: async (data) => {
      queryClient.invalidateQueries({ queryKey: ["userEmails"] });

      // Don't clear the form if the email was invalid or already exists
      if (data.startEmailAuthentication.status !== "STARTED") {
        return;
      }

      if (!data.startEmailAuthentication.authentication?.id) {
        throw new Error("Unexpected response from server");
      }

      // Call the onAdd callback
      await onAdd(data.startEmailAuthentication.authentication?.id);
    },
  });

  const handleSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
      e.preventDefault();

      const formData = new FormData(e.currentTarget);
      const email = formData.get("input") as string;
      let password = undefined;
      if (shouldPromptPassword) {
        password = await promptPassword();
      }

      const data = await addEmail.mutateAsync({
        email,
        password,
        language: i18n.languages[0],
      });

      if (data.startEmailAuthentication.status !== "STARTED") {
        // This is so that the 'Edit in place' component doesn't show a 'Saved' message
        throw new Error();
      }
    },
    [
      addEmail.mutateAsync,
      shouldPromptPassword,
      promptPassword,
      i18n.languages,
    ],
  );

  const status = addEmail.data?.startEmailAuthentication.status ?? null;
  const violations = addEmail.data?.startEmailAuthentication.violations ?? [];

  return (
    <>
      <PasswordConfirmationModal
        title={t("frontend.add_email_form.password_confirmation")}
        ref={passwordConfirmationRef}
      />
      <EditInPlace
        onSave={handleSubmit}
        required
        type="email"
        serverInvalid={!!status && status !== "STARTED"}
        label={t("frontend.add_email_form.email_field_label")}
        helpLabel={t("frontend.add_email_form.email_field_help")}
        saveButtonLabel={t("action.save")}
        savingLabel={t("common.saving")}
        savedLabel={t("common.saved")}
        cancelButtonLabel={t("action.cancel")}
      >
        <ErrorMessage
          match="typeMismatch"
          forceMatch={status === "INVALID_EMAIL_ADDRESS"}
        >
          {t("frontend.add_email_form.email_invalid_error")}
        </ErrorMessage>

        {status === "IN_USE" && (
          <ErrorMessage>
            {t("frontend.add_email_form.email_in_use_error")}
          </ErrorMessage>
        )}

        {status === "RATE_LIMITED" && (
          <ErrorMessage>
            {t("frontend.errors.rate_limit_exceeded")}
          </ErrorMessage>
        )}

        {status === "DENIED" && (
          <>
            <ErrorMessage>
              {t("frontend.add_email_form.email_denied_error")}
            </ErrorMessage>

            {violations.map((violation) => (
              // XXX: those messages are bad, but it's better to show them than show a generic message
              <HelpMessage key={violation}>{violation}</HelpMessage>
            ))}
          </>
        )}

        {status === "INCORRECT_PASSWORD" && (
          <ErrorMessage>
            {t("frontend.add_email_form.incorrect_password_error")}
          </ErrorMessage>
        )}
      </EditInPlace>
    </>
  );
};

export default AddEmailForm;
