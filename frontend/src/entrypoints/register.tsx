// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as v from "valibot";
import {
  PasswordRegisterForm,
  ProvidersOnlyForm,
} from "../components/RegisterForm";
import { setGraphqlEndpoint } from "../graphql";
import { mountIsland } from "../utils/mountIsland";
import {
  fieldStateSchema,
  providerSchema,
  serverErrorSchema,
} from "../utils/registration";
import "./shared.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A username check is cheap to redo and pointless to retry: a failure
      // just falls back to the neutral "couldn't check" message.
      retry: false,
      refetchOnWindowFocus: false,
      staleTime: 60_000,
    },
  },
});

// Parsed from the mount node's `data-*` attributes; structured values are
// JSON-encoded by the template.
const schema = v.object({
  csrfToken: v.string(),
  graphqlEndpoint: v.string(),
  captchaConfig: v.optional(
    v.pipe(
      v.string(),
      v.parseJson(),
      v.object({
        service: v.picklist([
          "recaptcha_v2",
          "cloudflare_turnstile",
          "hcaptcha",
        ]),
        site_key: v.string(),
      }),
    ),
  ),
  branding: v.pipe(
    v.string(),
    v.parseJson(),
    v.object({
      server_name: v.string(),
      tos_uri: v.optional(v.nullable(v.string())),
    }),
  ),
  features: v.pipe(
    v.string(),
    v.parseJson(),
    v.object({
      password_registration: v.boolean(),
      password_registration_email_required: v.boolean(),
      minimum_password_complexity: v.number(),
    }),
  ),
  form: v.pipe(
    v.string(),
    v.parseJson(),
    v.object({
      errors: v.array(serverErrorSchema),
      fields: v.record(v.string(), fieldStateSchema),
    }),
  ),
  providers: v.pipe(v.string(), v.parseJson(), v.array(providerSchema)),
  /** Href for the "already have an account?" call to action */
  loginLink: v.string(),
});

type Data = v.InferOutput<typeof schema>;

const RegisterPage: React.FC<{ data: Data }> = ({ data }) =>
  data.features.password_registration ? (
    <PasswordRegisterForm
      csrfToken={data.csrfToken}
      serverName={data.branding.server_name}
      tosUri={data.branding.tos_uri}
      emailRequired={data.features.password_registration_email_required}
      minimumPasswordComplexity={data.features.minimum_password_complexity}
      captchaConfig={data.captchaConfig}
      formErrors={data.form.errors}
      fields={data.form.fields}
      providers={data.providers}
      loginLink={data.loginLink}
    />
  ) : (
    <ProvidersOnlyForm
      csrfToken={data.csrfToken}
      providers={data.providers}
      loginLink={data.loginLink}
    />
  );

void mountIsland({
  id: "register-form",
  schema,
  render: (data) => {
    setGraphqlEndpoint(data.graphqlEndpoint);

    return (
      <QueryClientProvider client={queryClient}>
        <RegisterPage data={data} />
      </QueryClientProvider>
    );
  },
});
