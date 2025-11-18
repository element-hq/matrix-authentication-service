import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { Form } from "@vector-im/compound-web";
import { graphql } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { mountWithProviders } from "../mount";
import "../../shared.css";
import { useTranslation } from "react-i18next";
import PasswordCreationDoubleInput from "../../components/PasswordCreationDoubleInput";

const HTML_ID = "#password-double-input";

const QUERY = graphql(/* GraphQL */ `
  query PasswordChange {
    viewer {
      __typename
      ... on Node {
        id
      }
    }

    siteConfig {
      ...PasswordCreationDoubleInput_siteConfig
    }
  }
`);

const query = queryOptions({
  queryKey: ["passwordChange"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

type PasswordDoubleInputProps = { forceShowNewPasswordInvalid: boolean };

function PasswordDoubleInput({
  forceShowNewPasswordInvalid,
}: PasswordDoubleInputProps) {
  const {
    data: { siteConfig },
  } = useSuspenseQuery(query);
  const { t } = useTranslation();

  return (
    // Form.Root is needed because Form.Field requires to be included into a Form
    // asChild allows to replace Form.Root component by the child, the <form> used is in the password.html
    <Form.Root asChild>
      <div>
        <PasswordCreationDoubleInput
          siteConfig={siteConfig}
          forceShowNewPasswordInvalid={forceShowNewPasswordInvalid}
          newPasswordFieldName="password"
          newPasswordLabel={t("common.password")}
          newPasswordAgainFieldName="password_confirm"
          newPasswordAgainLabel={t("common.password_confirm")}
        />
      </div>
    </Form.Root>
  );
}

// Allow mounting under either the new specific id or the legacy #view
mountWithProviders(HTML_ID, PasswordDoubleInput);
