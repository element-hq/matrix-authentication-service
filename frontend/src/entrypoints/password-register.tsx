// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClientProvider } from "@tanstack/react-query";
import { Form, TooltipProvider } from "@vector-im/compound-web";
import { StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import * as v from "valibot";
import ErrorBoundary from "../components/ErrorBoundary";
import LoadingScreen from "../components/LoadingScreen";
import PasswordCreationDoubleInput from "../components/PasswordCreationDoubleInput";
import { queryClient } from "../graphql";
import i18n, { setupI18n } from "../i18n";
import "./shared.css";

setupI18n();

const schema = v.object({
  csrf_token: v.string(),
  form: v.object({
    errors: v.array(v.any()),
    fields: v.object({}),
  }),
});

const el = document.getElementById("password-register-form") as HTMLElement;
const data = v.parse(schema, (window as any).RENDER_DATA);

createRoot(el).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ErrorBoundary>
        <TooltipProvider>
          <Suspense fallback={<LoadingScreen />}>
            <I18nextProvider i18n={i18n}>
              <Form.Root method="POST">
                <input type="hidden" name="csrf" value={data.csrf_token} />
                <Form.Field name="username">
                  <Form.Label>Username</Form.Label>
                  <Form.TextControl
                    required
                    autoComplete="username"
                    autoCorrect="off"
                    autoCapitalize="none"
                  />
                </Form.Field>

                <Form.Field name="email">
                  <Form.Label>Email</Form.Label>
                  <Form.TextControl type="email" required />
                  <Form.ErrorMessage match="typeMismatch">
                    That's not an email
                  </Form.ErrorMessage>
                </Form.Field>

                <PasswordCreationDoubleInput
                  minimumPasswordComplexity={3}
                  forceShowNewPasswordInvalid={false}
                />

                <Form.Submit>Continue</Form.Submit>
              </Form.Root>
            </I18nextProvider>
          </Suspense>
        </TooltipProvider>
      </ErrorBoundary>
    </QueryClientProvider>
  </StrictMode>,
);
