// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { act, screen } from "@testing-library/react";
import type { Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

/** The roots the entry point mounted, to unmount after each test */
const roots = vi.hoisted((): Root[] => []);

vi.mock("react-dom/client", async (importOriginal) => {
  const client = await importOriginal<typeof import("react-dom/client")>();
  return {
    ...client,
    createRoot: (...args: Parameters<typeof client.createRoot>): Root => {
      const root = client.createRoot(...args);
      roots.push(root);
      return root;
    },
  };
});

// The scorer loads its dictionaries lazily, which can outlive the test file
vi.mock("../utils/password_complexity", () => ({
  estimatePasswordComplexity: async () => ({
    score: 0,
    scoreText: "",
    improvementsText: [],
  }),
}));

const PROVIDERS = [
  { name: "First", brand: null, id: "01J00000000000000000000001" },
  { name: "Second", brand: null, id: "01J00000000000000000000002" },
];

/** Mount the island on a node carrying the given data, as the page does */
const mountRegister = async ({
  passwordRegistration = true,
  providers = [],
  invite,
  form = { errors: [], fields: {} },
}: {
  passwordRegistration?: boolean;
  providers?: typeof PROVIDERS;
  invite?: Record<string, unknown>;
  form?: Record<string, unknown>;
} = {}): Promise<void> => {
  const el = document.createElement("div");
  el.id = "register-form";
  el.dataset.csrfToken = "csrf";
  el.dataset.branding = JSON.stringify({ server_name: "example.com" });
  el.dataset.features = JSON.stringify({
    password_registration: passwordRegistration,
    password_registration_email_required: true,
    minimum_password_complexity: 1,
  });
  el.dataset.form = JSON.stringify(form);
  el.dataset.providers = JSON.stringify(providers);
  el.dataset.loginLink = "/login";
  if (invite) el.dataset.invite = JSON.stringify(invite);
  document.body.append(el);

  // The entry point mounts the island when it is imported
  vi.resetModules();
  await import("./register");
  await screen.findByRole("link", { name: "Already have an account?" });
};

const unmount = (): void => {
  act(() => {
    for (const root of roots.splice(0)) root.unmount();
  });
  document.body.innerHTML = "";
};

describe("register island", () => {
  // The first import of the entry point is slow, so it happens outside the
  // tests' timeout
  beforeAll(async () => {
    await mountRegister();
    unmount();
  });

  afterEach(unmount);

  describe("with an invalid invite", () => {
    it.each([
      0, 1, 2,
    ])("says so without password registration, with %i providers", async (count) => {
      await mountRegister({
        passwordRegistration: false,
        providers: PROVIDERS.slice(0, count),
        invite: { valid: false },
      });

      expect(screen.getByRole("alert")).toHaveTextContent(
        "This invite link is invalid or has expired",
      );
      expect(
        screen.queryAllByRole("button", { name: /^Continue with/ }),
      ).toHaveLength(count);
    });

    it("says so above the password form", async () => {
      await mountRegister({ invite: { valid: false } });

      const alert = screen.getByRole("alert");
      expect(alert).toHaveTextContent(
        "This invite link is invalid or has expired",
      );
      expect(
        alert.compareDocumentPosition(screen.getByLabelText("Username")) &
          Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
    });
  });
});
