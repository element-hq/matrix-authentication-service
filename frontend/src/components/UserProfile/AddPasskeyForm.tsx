// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation } from "@tanstack/react-query";
import { Alert, Button } from "@vector-im/compound-web";
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
  mutation CompleteRegisterPasskey($id: ID!, $response: String!) {
    completeRegisterPasskey(input: { id: $id, response: $response }) {
      status
      error
    }
  }
`);

const AddPasskeyForm: React.FC = () => {
  const { t } = useTranslation();
  const register = useMutation({
    throwOnError: false,
    mutationFn: async () => {
      const {
        startRegisterPasskey: { id, options },
      } = await graphqlRequest({
        query: START_REGISTER_PASSKEY_PAYLOAD,
      });

      const response = await performRegistration(options);

      return await graphqlRequest({
        query: COMPLETE_REGISTER_PASSKEY_PAYLOAD,
        variables: { id, response },
      });
    },
    onSuccess: async (_data, _variables, _onMutateResult, { client }) => {
      await client.invalidateQueries({ queryKey: ["userPasskeys"] });
    },
  });

  const handleClick = async (
    e: React.FormEvent<HTMLButtonElement>,
  ): Promise<void> => {
    e.preventDefault();
    register.mutate();
  };

  const support = checkSupport();
  const status = register.data?.completeRegisterPasskey.status ?? null;

  return (
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
          title={t("frontend.account.passkeys.response_invalid_error")}
        />
      )}
      {status === "EXISTS" && (
        <Alert
          type="critical"
          title={t("frontend.account.passkeys.exists_error")}
        />
      )}
      {register.error && register.error.name !== "NotAllowedError" && (
        <Alert type="critical" title={register.error.toString()} />
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
  );
};

export default AddPasskeyForm;
