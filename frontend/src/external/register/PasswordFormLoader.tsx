import {
  useSuspenseQuery,
  queryOptions,
} from "@tanstack/react-query";
import { graphql } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { Form } from "@vector-im/compound-web";
import "../../shared.css";
import { type FormEvent } from "react";
import PasswordCreationDoubleInput from "../../components/PasswordCreationDoubleInput";


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

export default function PasswordFormLoader({
    forceShowNewPasswordInvalid,
  }: {
    forceShowNewPasswordInvalid: boolean;
  }): React.ReactElement {
  const {
    data: { siteConfig },
  } = useSuspenseQuery(query);

  return (
    <Form.Root asChild>
      <div>
        <PasswordCreationDoubleInput
          siteConfig={siteConfig}
          forceShowNewPasswordInvalid={forceShowNewPasswordInvalid}
        />
      </div>
    </Form.Root>
  );
}
