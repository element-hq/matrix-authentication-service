// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { TFunction } from "i18next";
import * as v from "valibot";

/** Shape of both the form-level and the field-level errors the server sends. */
export const serverErrorSchema = v.object({
  kind: v.string(),
  code: v.optional(v.nullable(v.string())),
  message: v.optional(v.string()),
});

export type ServerError = v.InferOutput<typeof serverErrorSchema>;

/** Valid Matrix localpart: lowercase ascii, digits, and a few special chars */
export const VALID_LOCALPART_RE = /^[a-z0-9._=/+-]+$/;

/** Normalize a username: trim and lowercase. */
export const normalizeUsername = (value: string): string =>
  value.trim().toLocaleLowerCase();

/** Whether a normalized username is worth sending to the availability check. */
export const isUsernameCheckable = (normalized: string): boolean =>
  normalized.length > 0 && VALID_LOCALPART_RE.test(normalized);

/**
 * Well-known policy violation codes, mapped to the key of their translated
 * message. Codes we don't know about fall back to the server's own message.
 */
const POLICY_CODE_MESSAGES = {
  "username-too-short": "frontend.errors.username_too_short",
  "username-too-long": "frontend.errors.username_too_long",
  "username-invalid-chars": "frontend.errors.username_invalid_chars",
  "username-all-numeric": "frontend.errors.username_all_numeric",
  "username-banned": "frontend.errors.username_banned",
  "username-not-allowed": "frontend.errors.username_not_allowed",
  "email-domain-not-allowed": "frontend.errors.email_domain_not_allowed",
  "email-domain-banned": "frontend.errors.email_domain_banned",
  "email-not-allowed": "frontend.errors.email_not_allowed",
  "email-banned": "frontend.errors.email_banned",
  "password-too-weak": "frontend.password_strength.too_weak",
} as const;

/**
 * Translate a policy violation code, or return `undefined` if the code is
 * unknown to this version of the frontend.
 */
export const policyCodeMessage = (
  t: TFunction,
  code: string,
): string | undefined => {
  const key = POLICY_CODE_MESSAGES[code as keyof typeof POLICY_CODE_MESSAGES];
  return key ? t(key) : undefined;
};

/** Translate a server-side field error. */
export const fieldErrorMessage = (t: TFunction, error: ServerError): string => {
  switch (error.kind) {
    case "required":
      return t("frontend.errors.field_required");
    case "exists":
      return t("frontend.errors.username_taken");
    case "password_mismatch":
      return t("frontend.errors.password_mismatch");
    case "policy":
      return (
        (error.code ? policyCodeMessage(t, error.code) : undefined) ??
        error.message ??
        t("frontend.errors.field_invalid")
      );
    // The server marks a malformed email as 'invalid', and uses
    // 'unspecified' for errors it doesn't want to detail
    case "invalid":
    case "unspecified":
      return t("frontend.errors.field_invalid");
    default:
      return error.message ?? t("frontend.errors.field_invalid");
  }
};

/** Translate a server-side form error. */
export const formErrorMessage = (t: TFunction, error: ServerError): string => {
  switch (error.kind) {
    case "captcha":
      return t("frontend.errors.captcha");
    case "rate_limit_exceeded":
      return t("frontend.errors.rate_limit_exceeded");
    case "password_mismatch":
      return t("frontend.errors.password_mismatch");
    case "policy":
      return (
        (error.code ? policyCodeMessage(t, error.code) : undefined) ??
        error.message ??
        t("frontend.errors.unspecified")
      );
    default:
      return error.message ?? t("frontend.errors.unspecified");
  }
};
