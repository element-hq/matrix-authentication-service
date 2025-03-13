// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { setupI18n } from "./i18n";
import { checkSupport, performAuthentication } from "./utils/webauthn";

const t = await setupI18n();

interface IWindow {
  WEBAUTHN_OPTIONS?: string;
}

const options =
  typeof window !== "undefined" && (window as IWindow).WEBAUTHN_OPTIONS;

const errors = document.getElementById("errors");
const retryButtonContainer = document.getElementById("retry-button-container");
const retryButton = document.getElementById("retry-button");
const form = document.getElementById("passkey-form");
const formResponse = form?.querySelector('[name="response"]');

function setError(text: string) {
  const error = document.createElement("div");
  error.classList.add("text-critical", "font-medium");
  error.innerText = text;
  errors?.appendChild(error);
}

async function run() {
  if (!options) {
    throw new Error("WEBAUTHN_OPTIONS is not defined");
  }

  if (
    !errors ||
    !retryButtonContainer ||
    !retryButton ||
    !form ||
    !formResponse
  ) {
    throw new Error("Missing elements in document");
  }

  errors.innerHTML = "";

  if (!checkSupport()) {
    setError(t("frontend.account.passkeys.not_supported"));
    return;
  }

  try {
    const response = await performAuthentication(options);
    (formResponse as HTMLInputElement).value = response;
    (form as HTMLFormElement).submit();
  } catch (e) {
    if (e instanceof Error && e.name !== "NotAllowedError") {
      setError(e.toString());
    }
    retryButtonContainer?.classList.remove("hidden");
    return;
  }
}

if (!errors?.children.length) {
  run();
} else {
  retryButtonContainer?.classList.remove("hidden");
}

retryButton?.addEventListener("click", () => {
  run();
});
