// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { QueryClientProvider } from "@tanstack/react-query";
import { StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import LoadingSpinner from "./components/LoadingSpinner";
import PasskeyLoginButton from "./components/PasskeyLoginButton";
import { queryClient } from "./graphql";
import i18n, { setupI18n } from "./i18n";

setupI18n();

interface IWindow {
  WEBAUTHN_OPTIONS?: string;
}

const options =
  (typeof window !== "undefined" && (window as IWindow).WEBAUTHN_OPTIONS) ||
  undefined;

createRoot(document.getElementById("passkey-root") as HTMLElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <Suspense fallback={<LoadingSpinner />}>
        <I18nextProvider i18n={i18n}>
          <PasskeyLoginButton options={options} />
        </I18nextProvider>
      </Suspense>
    </QueryClientProvider>
  </StrictMode>,
);
