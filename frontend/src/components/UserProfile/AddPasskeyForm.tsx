// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Button,
  EditInPlace,
  ErrorMessage,
} from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { graphql } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { checkSupport, performRegistration } from "../../utils/webauthn";

const START_REGISTER_PASSKEY_PAYLOAD = graphql(/* GraphQL */ `
  mutation StartRegisterPasskey {
    startRegisterPasskey {
      id
      options
    }
  }
`);

const COMPLETE_REGISTER_PASSKEY_PAYLOAD = graphql(/* GraphQL */ `
  mutation CompleteRegisterPasskey(
    $id: ID!
    $name: String!
    $response: String!
  ) {
    completeRegisterPasskey(
      input: { id: $id, name: $name, response: $response }
    ) {
      status
      error
    }
  }
`);

const AddPasskeyForm: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const startRegister = useMutation({
    mutationFn: () =>
      graphqlRequest({
        query: START_REGISTER_PASSKEY_PAYLOAD,
      }),
    onSuccess: async (data) => {
      if (
        !data.startRegisterPasskey?.id ||
        !data.startRegisterPasskey?.options
      ) {
        throw new Error("Unexpected response from server");
      }

      webauthnCeremony.mutate(data.startRegisterPasskey.options);
      return;
    },
  });
  const webauthnCeremony = useMutation({
    mutationFn: async (options: string) => {
      try {
        // The error isn't getting caught by the library so instead returning with data
        const response = await performRegistration(options);
        return { response };
      } catch (e) {
        console.error(e);
        return { error: e as Error };
      }
    },
  });
  const completeRegister = useMutation({
    mutationFn: ({
      id,
      name,
      response,
    }: {
      id: string;
      name: string;
      response: string;
    }) =>
      graphqlRequest({
        query: COMPLETE_REGISTER_PASSKEY_PAYLOAD,
        variables: { id, name, response },
      }),
    onSuccess: async (data) => {
      // Just display error for the name field
      if (data.completeRegisterPasskey?.status === "INVALID_NAME") {
        return;
      }

      startRegister.reset();
      webauthnCeremony.reset();

      // If there was an error with the passkey registration itself, go back to the add button without resetting the error from this mutation
      if (
        data.completeRegisterPasskey?.status === "INVALID_CHALLENGE" ||
        data.completeRegisterPasskey?.status === "INVALID_RESPONSE" ||
        data.completeRegisterPasskey?.status === "EXISTS"
      ) {
        return;
      }

      queryClient.invalidateQueries({ queryKey: ["userPasskeys"] });

      completeRegister.reset();
    },
  });

  const handleClick = async (
    e: React.FormEvent<HTMLButtonElement>,
  ): Promise<void> => {
    e.preventDefault();

    if (startRegister.data?.startRegisterPasskey?.options) {
      // Reuse the registration we already have if it was interrupted by an error
      webauthnCeremony.mutate(startRegister.data.startRegisterPasskey.options);
    } else {
      await startRegister.mutateAsync();
    }
  };
  const handleSubmit = async (
    e: React.FormEvent<HTMLFormElement>,
  ): Promise<void> => {
    e.preventDefault();

    if (
      !startRegister.data?.startRegisterPasskey.id ||
      !webauthnCeremony.data?.response
    )
      return;

    const formData = new FormData(e.currentTarget);
    const name = formData.get("input") as string;

    await completeRegister.mutateAsync({
      id: startRegister.data?.startRegisterPasskey.id,
      name,
      response: webauthnCeremony.data?.response,
    });
  };

  const status = completeRegister.data?.completeRegisterPasskey.status ?? null;
  const support = checkSupport();

  return (
    <>
      {webauthnCeremony.data?.response ? (
        <EditInPlace
          onSave={handleSubmit}
          required
          type="text"
          serverInvalid={!!status && status !== "ADDED"}
          label={t("frontend.account.passkeys.name_field_label")}
          helpLabel={t("frontend.account.passkeys.name_field_help")}
          saveButtonLabel={t("action.save")}
          savingLabel={t("common.saving")}
          savedLabel={t("common.saved")}
          cancelButtonLabel={t("action.cancel")}
        >
          <ErrorMessage
            match="typeMismatch"
            forceMatch={status === "INVALID_NAME"}
          >
            {t("frontend.account.passkeys.name_invalid_error")}
          </ErrorMessage>
        </EditInPlace>
      ) : (
        <>
          {status === "INVALID_CHALLENGE" && (
            <Alert
              type="critical"
              title={t("frontend.account.passkeys.challenge_invalid_error")}
            />
          )}
          {status === "INVALID_RESPONSE" && (
            <Alert
              type="critical"
              title={t("frontend.account.passkeys.response_invalid_error", {
                error: completeRegister.data?.completeRegisterPasskey.error,
              })}
            />
          )}
          {status === "EXISTS" && (
            <Alert
              type="critical"
              title={t("frontend.account.passkeys.exists_error")}
            />
          )}
          {webauthnCeremony.data?.error &&
            webauthnCeremony.data?.error.name !== "NotAllowedError" && (
              <Alert
                type="critical"
                title={webauthnCeremony.data?.error.toString()}
              />
            )}
          <Button
            kind="primary"
            disabled={!support}
            size="lg"
            onClick={handleClick}
          >
            {t("frontend.account.passkeys.add")}
          </Button>
        </>
      )}
    </>
  );
};

export default AddPasskeyForm;
