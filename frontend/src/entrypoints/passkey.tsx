// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { QueryClientProvider } from "@tanstack/react-query";
import { StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import * as v from "valibot";
import LoadingSpinner from "../components/LoadingSpinner";
import PasskeyLoginButton from "../components/PasskeyLoginButton";
import { queryClient } from "../graphql";
import i18n, { setupI18n } from "../i18n";

await setupI18n();

const root = document.getElementById("passkey-root");
if (!root) {
  throw new Error("Passkey root element not found");
}

const PublicKeyCredentialRequestOptionsJSONSchema = v.object({
  allowCredentials: v.optional(
    v.array(
      v.object({
        id: v.string(),
        transports: v.optional(v.array(v.string())),
        type: v.string(),
      }),
    ),
  ),
  challenge: v.string(),
  extensions: v.optional(
    v.object({
      appid: v.optional(v.string()),
      credProps: v.optional(v.boolean()),
      largeBlob: v.optional(
        v.object({
          read: v.optional(v.boolean()),
          support: v.optional(v.string()),
          write: v.optional(v.string()),
        }),
      ),
      prf: v.optional(
        v.object({
          eval: v.optional(
            v.object({
              first: v.string(),
              second: v.optional(v.string()),
            }),
          ),
          evalByCredential: v.optional(
            v.record(
              v.string(),
              v.object({
                first: v.string(),
                second: v.optional(v.string()),
              }),
            ),
          ),
        }),
      ),
    }),
  ),
  hints: v.optional(v.array(v.string())),
  rpId: v.optional(v.string()),
  timeout: v.optional(v.number()),
  userVerification: v.optional(v.string()),
});

const ElementDataSchema = v.object({
  webauthnOptions: v.pipe(
    v.string(),
    v.parseJson(),
    PublicKeyCredentialRequestOptionsJSONSchema,
  ),
  webauthnChallengeId: v.string(),
  csrfToken: v.string(),
});

const { webauthnChallengeId, webauthnOptions, csrfToken } = v.parse(
  ElementDataSchema,
  root.dataset,
);

createRoot(document.getElementById("passkey-root") as HTMLElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <Suspense fallback={<LoadingSpinner inline />}>
        <I18nextProvider i18n={i18n}>
          <PasskeyLoginButton
            challengeId={webauthnChallengeId}
            options={webauthnOptions}
            csrfToken={csrfToken}
          />
        </I18nextProvider>
      </Suspense>
    </QueryClientProvider>
  </StrictMode>,
);
