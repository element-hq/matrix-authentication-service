import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { Form } from "@vector-im/compound-web";
import { graphql } from "../../gql";
import { graphqlRequest } from "../../graphql";
import "../../shared.css";
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
    //Form.Root is needed because Form.Field requires to be included into a Form
    //asChild allows to replace Form.Root component by the child, the <form> used is in the password.html
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
