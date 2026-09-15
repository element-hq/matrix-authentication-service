// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useQuery } from "@tanstack/react-query";
import { Form, InlineSpinner } from "@vector-im/compound-web";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { graphql } from "../../gql";
import { graphqlRequest } from "../../graphql";
import {
  fieldErrorMessage,
  isUsernameCheckable,
  normalizeUsername,
  policyCodeMessage,
  type ServerError,
  VALID_LOCALPART_RE,
} from "../../utils/registration";
import { useDebouncedValue } from "../../utils/useDebouncedValue";
import FieldMessageSlot from "../FieldMessageSlot";
import PasswordComplexityFeedback from "../PasswordComplexityFeedback";

const USERNAME_AVAILABLE_QUERY = graphql(`
  query UsernameAvailable($username: String!) {
    usernameAvailable(username: $username) {
      available
      reason
      violationCodes
    }
  }
`);

/**
 * The settled result of the live availability check. Rendered inside an
 * `aria-live` region, so it must only ever hold states the user has stopped
 * typing into.
 */
const UsernameVerdict: React.FC<{
  checking: boolean;
  checkFailed: boolean;
  availability?: {
    available: boolean;
    reason?: string | null;
    violationCodes?: readonly string[] | null;
  };
}> = ({ checking, checkFailed, availability }) => {
  const { t } = useTranslation();

  if (checking) {
    const label = t("frontend.register.username_checking");
    return (
      <Form.HelpMessage>
        {/* The spinner carries the accessible name, so the live region doesn't
            announce the same text twice */}
        <InlineSpinner role="img" aria-label={label} />
        <span aria-hidden="true">{label}</span>
      </Form.HelpMessage>
    );
  }

  if (checkFailed) {
    return (
      <Form.HelpMessage>
        {t("frontend.register.username_check_failed")}
      </Form.HelpMessage>
    );
  }

  if (!availability) return null;

  if (availability.available) {
    return (
      <Form.SuccessMessage match="valid" forceMatch>
        {t("frontend.register.username_available")}
      </Form.SuccessMessage>
    );
  }

  if (availability.reason === "INVALID") {
    const messages = (availability.violationCodes ?? [])
      .map((code) => policyCodeMessage(t, code))
      .filter((message): message is string => message !== undefined);

    return (
      <>
        {(messages.length > 0
          ? messages
          : [t("frontend.errors.username_invalid")]
        ).map((message) => (
          <Form.ErrorMessage key={message} match="badInput" forceMatch>
            {message}
          </Form.ErrorMessage>
        ))}
      </>
    );
  }

  return (
    <Form.ErrorMessage match="badInput" forceMatch>
      {t("frontend.errors.username_taken")}
    </Form.ErrorMessage>
  );
};

export const UsernameField: React.FC<{
  serverName: string;
  defaultValue: string;
  serverErrors: ServerError[];
}> = ({ serverName, defaultValue, serverErrors }) => {
  const { t } = useTranslation();
  const [username, setUsername] = useState(defaultValue);
  // The value the page was rendered with has been checked by the POST already
  const [dirty, setDirty] = useState(false);

  const normalized = normalizeUsername(username);
  const debounced = useDebouncedValue(normalized, 500);
  const isDebouncePending = normalized !== debounced;

  const { data, isFetching, isError } = useQuery({
    queryKey: ["usernameAvailable", debounced],
    queryFn: ({ signal }) =>
      graphqlRequest({
        query: USERNAME_AVAILABLE_QUERY,
        variables: { username: debounced },
        signal,
      }),
    enabled: dirty && isUsernameCheckable(debounced),
  });

  const settled = dirty && !isDebouncePending;
  const checking =
    dirty &&
    isUsernameCheckable(normalized) &&
    (isFetching || isDebouncePending);
  const availability = settled ? data?.usernameAvailable : undefined;

  return (
    <Form.Field
      name="username"
      // Only actual POST-returned errors make the control invalid: flipping
      // this from the live check would steal the focus while typing
      serverInvalid={serverErrors.length > 0}
    >
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
          setDirty(true);
        }}
        onBlur={() => setUsername(normalizeUsername(username))}
      />

      {/* Outside the live region: it changes on every keystroke */}
      <Form.HelpMessage>{`@${normalized || "—"}:${serverName}`}</Form.HelpMessage>

      <div aria-live="polite" aria-busy={checking}>
        <UsernameVerdict
          checking={checking}
          checkFailed={settled && isError}
          availability={availability}
        />
      </div>

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
