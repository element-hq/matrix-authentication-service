// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Form } from "@vector-im/compound-web";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  fieldErrorMessage,
  normalizeUsername,
  type ServerError,
  VALID_LOCALPART_RE,
} from "../../utils/registration";
import FieldMessageSlot from "../FieldMessageSlot";
import PasswordComplexityFeedback from "../PasswordComplexityFeedback";

export const UsernameField: React.FC<{
  serverName: string;
  defaultValue: string;
  serverErrors: ServerError[];
}> = ({ serverName, defaultValue, serverErrors }) => {
  const { t } = useTranslation();
  const [username, setUsername] = useState(defaultValue);

  const normalized = normalizeUsername(username);

  return (
    <Form.Field name="username" serverInvalid={serverErrors.length > 0}>
      <Form.Label>{t("common.username")}</Form.Label>
      <Form.TextControl
        required
        autoComplete="username"
        autoCorrect="off"
        autoCapitalize="none"
        value={username}
        onChange={(e) => {
          // Lowercase as the user types, so what is shown is what gets sent
          setUsername(e.target.value.toLowerCase());
        }}
        onBlur={() => setUsername(normalizeUsername(username))}
      />

      <Form.HelpMessage>{`@${normalized || "—"}:${serverName}`}</Form.HelpMessage>

      <Form.ErrorMessage match="valueMissing">
        {t("frontend.errors.field_required")}
      </Form.ErrorMessage>
      <Form.ErrorMessage
        match={(value) => {
          const n = normalizeUsername(value);
          return n.length > 0 && !VALID_LOCALPART_RE.test(n);
        }}
      >
        {t("frontend.errors.username_invalid")}
      </Form.ErrorMessage>

      {serverErrors.map((error, index) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
        <Form.ErrorMessage key={`${error.kind}-${index}`}>
          {fieldErrorMessage(t, error)}
        </Form.ErrorMessage>
      ))}
    </Form.Field>
  );
};

export const PasswordFields: React.FC<{
  autoFocus?: boolean;
  minimumPasswordComplexity: number;
  serverErrors: ServerError[];
  confirmServerErrors: ServerError[];
}> = ({
  autoFocus,
  minimumPasswordComplexity,
  serverErrors,
  confirmServerErrors,
}) => {
  const { t } = useTranslation();
  const confirmRef = useRef<HTMLInputElement>(null);
  const [password, setPassword] = useState("");

  return (
    <>
      <Form.Field name="password" serverInvalid={serverErrors.length > 0}>
        <Form.Label>{t("frontend.register.password_label")}</Form.Label>

        <Form.PasswordControl
          required
          autoComplete="new-password"
          autoFocus={autoFocus}
          // Re-check the confirmation once the first field settles, so a stale
          // "no match" error doesn't stick around
          onBlur={() =>
            confirmRef.current?.value && confirmRef.current.reportValidity()
          }
          onChange={(e) => setPassword(e.target.value)}
        />

        <PasswordComplexityFeedback
          password={password}
          minimumPasswordComplexity={minimumPasswordComplexity}
        />

        <Form.ErrorMessage match="valueMissing">
          {t("frontend.errors.field_required")}
        </Form.ErrorMessage>

        {serverErrors.map((error, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
          <Form.ErrorMessage key={`${error.kind}-${index}`}>
            {fieldErrorMessage(t, error)}
          </Form.ErrorMessage>
        ))}
      </Form.Field>

      <Form.Field
        name="password_confirm"
        serverInvalid={confirmServerErrors.length > 0}
      >
        <Form.Label>{t("frontend.register.password_confirm_label")}</Form.Label>

        <Form.PasswordControl
          required
          ref={confirmRef}
          autoComplete="new-password"
        />

        <FieldMessageSlot>
          <Form.ErrorMessage match="valueMissing">
            {t("frontend.errors.field_required")}
          </Form.ErrorMessage>

          <Form.ErrorMessage
            match={(value, form) => value !== form.get("password")}
          >
            {t("frontend.password_change.passwords_no_match")}
          </Form.ErrorMessage>

          <Form.SuccessMessage match="valid">
            {t("frontend.password_change.passwords_match")}
          </Form.SuccessMessage>

          {confirmServerErrors.map((error, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
            <Form.ErrorMessage key={`${error.kind}-${index}`}>
              {fieldErrorMessage(t, error)}
            </Form.ErrorMessage>
          ))}
        </FieldMessageSlot>
      </Form.Field>
    </>
  );
};
