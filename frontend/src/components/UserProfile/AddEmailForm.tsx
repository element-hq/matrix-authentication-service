// Copyright 2024 New Vector Ltd.
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
import { useTranslation } from "react-i18next";
import { graphql } from "../../gql";
import { graphqlRequest } from "../../graphql";

const ADD_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation AddEmail($email: String!, $language: String!) {
    startEmailAuthentication(input: { email: $email, language: $language }) {
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
}> = ({ onAdd }) => {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const addEmail = useMutation({
    mutationFn: ({ email, language }: { email: string; language: string }) =>
      graphqlRequest({
        query: ADD_EMAIL_MUTATION,
        variables: { email, language },
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

  const handleSubmit = async (
    e: React.FormEvent<HTMLFormElement>,
  ): Promise<void> => {
    e.preventDefault();

    const formData = new FormData(e.currentTarget);
    const email = formData.get("input") as string;
    addEmail.mutate({ email, language: i18n.languages[0] });
  };

  const status = addEmail.data?.startEmailAuthentication.status ?? null;
  const violations = addEmail.data?.startEmailAuthentication.violations ?? [];

  return (
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
    </EditInPlace>
  );
};

export default AddEmailForm;
