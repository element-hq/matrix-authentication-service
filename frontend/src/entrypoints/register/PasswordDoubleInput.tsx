import {
  QueryClient,
  QueryClientProvider,
  queryOptions,
  useSuspenseQuery,
} from "@tanstack/react-query";
import { Form, TooltipProvider } from "@vector-im/compound-web";
import { StrictMode, Suspense } from "react";
import ReactDOM from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import ErrorBoundary from "../../components/ErrorBoundary";
import PasswordCreationDoubleInput from "../../components/PasswordCreationDoubleInput";
import { graphql } from "../../gql";
import { graphqlRequest } from "../../graphql";
import i18n, { setupI18n } from "../../i18n";
import "../shared.css";

setupI18n();

const HTML_CONTAINER_ID = "password-double-input";

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

function PasswordDoubleInput() {
  const {
    data: { siteConfig },
  } = useSuspenseQuery(query);

  return (
    <Form.Root asChild>
      <div>
        <PasswordCreationDoubleInput
          siteConfig={siteConfig}
          forceShowNewPasswordInvalid={false}
          variant="register"
        />
      </div>
    </Form.Root>
  );
}

function mountComponentWithProviders(containerId: string) {
  try {
    const el = document.getElementById(containerId);
    if (!el) throw new Error(`can not find ${containerId} in DOM`);

    const queryClient = new QueryClient();

    ReactDOM.createRoot(el).render(
      <StrictMode>
        <QueryClientProvider client={queryClient}>
          <ErrorBoundary>
            <TooltipProvider>
              <Suspense fallback={<div>{`Loading... ${containerId}…`}</div>}>
                <I18nextProvider i18n={i18n}>
                  <PasswordDoubleInput />
                </I18nextProvider>
              </Suspense>
            </TooltipProvider>
          </ErrorBoundary>
        </QueryClientProvider>
      </StrictMode>,
    );
  } catch (err) {
    console.error(
      `Cannot mount component PasswordCreationDoubleInput on ${containerId}:`,
      err,
    );
  }
}

mountComponentWithProviders(HTML_CONTAINER_ID);
