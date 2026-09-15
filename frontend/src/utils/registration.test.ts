// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { TFunction } from "i18next";
import { describe, expect, it } from "vitest";

import {
  fieldErrorMessage,
  formErrorMessage,
  isUsernameCheckable,
  normalizeUsername,
  policyCodeMessage,
} from "./registration";

// Echoes back the key, so the tests assert on which key was picked
const t = ((key: string) => key) as unknown as TFunction;

describe("normalizeUsername()", () => {
  it("trims and lowercases", () => {
    expect(normalizeUsername("  Alice  ")).toBe("alice");
    expect(normalizeUsername("ÉLODIE")).toBe("élodie");
    expect(normalizeUsername("")).toBe("");
  });
});

describe("isUsernameCheckable()", () => {
  it("accepts valid localparts", () => {
    expect(isUsernameCheckable("alice")).toBe(true);
    expect(isUsernameCheckable("a.b_c-d=e/f+g0")).toBe(true);
  });

  it("rejects empty and invalid localparts", () => {
    expect(isUsernameCheckable("")).toBe(false);
    expect(isUsernameCheckable("Alice")).toBe(false);
    expect(isUsernameCheckable("alice bob")).toBe(false);
    expect(isUsernameCheckable("élodie")).toBe(false);
  });
});

describe("policyCodeMessage()", () => {
  it("translates known codes", () => {
    expect(policyCodeMessage(t, "username-too-short")).toBe(
      "frontend.errors.username_too_short",
    );
    expect(policyCodeMessage(t, "password-too-weak")).toBe(
      "frontend.password_strength.too_weak",
    );
  });

  it("returns undefined for unknown codes", () => {
    expect(policyCodeMessage(t, "something-new")).toBeUndefined();
  });
});

describe("fieldErrorMessage()", () => {
  it("maps well-known kinds", () => {
    expect(fieldErrorMessage(t, { kind: "required" })).toBe(
      "frontend.errors.field_required",
    );
    expect(fieldErrorMessage(t, { kind: "exists" })).toBe(
      "frontend.errors.username_taken",
    );
    expect(fieldErrorMessage(t, { kind: "invalid" })).toBe(
      "frontend.errors.field_invalid",
    );
  });

  it("prefers the policy code over the server message", () => {
    expect(
      fieldErrorMessage(t, {
        kind: "policy",
        code: "username-banned",
        message: "nope",
      }),
    ).toBe("frontend.errors.username_banned");
  });

  it("falls back to the server message for unknown policy codes", () => {
    expect(
      fieldErrorMessage(t, {
        kind: "policy",
        code: "something-new",
        message: "nope",
      }),
    ).toBe("nope");
    expect(
      fieldErrorMessage(t, { kind: "policy", code: "something-new" }),
    ).toBe("frontend.errors.field_invalid");
  });

  it("falls back to the server message for unknown kinds", () => {
    expect(fieldErrorMessage(t, { kind: "brand_new", message: "nope" })).toBe(
      "nope",
    );
    expect(fieldErrorMessage(t, { kind: "brand_new" })).toBe(
      "frontend.errors.field_invalid",
    );
  });
});

describe("formErrorMessage()", () => {
  it("maps well-known kinds", () => {
    expect(formErrorMessage(t, { kind: "captcha" })).toBe(
      "frontend.errors.captcha",
    );
    expect(formErrorMessage(t, { kind: "rate_limit_exceeded" })).toBe(
      "frontend.errors.rate_limit_exceeded",
    );
  });

  it("falls back to the server message, then to a generic one", () => {
    expect(formErrorMessage(t, { kind: "brand_new", message: "nope" })).toBe(
      "nope",
    );
    expect(formErrorMessage(t, { kind: "brand_new" })).toBe(
      "frontend.errors.unspecified",
    );
  });
});
