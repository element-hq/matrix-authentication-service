// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClient, useQuery } from "@tanstack/react-query";
import { Button, Form, InlineSpinner } from "@vector-im/compound-web";
import { useCallback, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import * as v from "valibot";
import { CaptchaSection } from "../components/Captcha";
import PasswordComplexityFeedback from "../components/PasswordComplexityFeedback";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";
import { mountIsland } from "../utils/mountIsland";
import {
  fieldErrorMessage,
  formErrorMessage,
  isUsernameCheckable,
  normalizeUsername,
  policyCodeMessage,
  type ServerError,
  serverErrorSchema,
  VALID_LOCALPART_RE,
} from "../utils/registration";
import { useDebouncedValue } from "../utils/useDebouncedValue";
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

const fieldStateSchema = v.object({
  value: v.optional(v.nullable(v.string())),
  errors: v.array(serverErrorSchema),
});

// Parsed from the mount node's `data-*` attributes; structured values are
// JSON-encoded by the template.
const schema = v.object({
  csrfToken: v.string(),
  graphqlEndpoint: v.string(),
  loginLink: v.string(),
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
});

type Data = v.InferOutput<typeof schema>;

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

const UsernameField: React.FC<{
  serverName: string;
  defaultValue: string;
  serverErrors: ServerError[];
}> = ({ serverName, defaultValue, serverErrors }) => {
  const { t } = useTranslation();
  const [username, setUsername] = useState(defaultValue);
  // Until the user edits the field, what the POST came back with is the truth
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

  return (
    <Form.Field
      name="username"
      // Only actual POST-returned errors make the control invalid: flipping
      // this from the live check would steal the focus while typing
      serverInvalid={!dirty && serverErrors.length > 0}
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
          setUsername(e.target.value.toLocaleLowerCase());
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
          availability={settled ? data?.usernameAvailable : undefined}
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

      {!dirty &&
        serverErrors.map((error, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
          <Form.ErrorMessage key={`${error.kind}-${index}`}>
            {fieldErrorMessage(t, error)}
          </Form.ErrorMessage>
        ))}
    </Form.Field>
  );
};

const PasswordFields: React.FC<{
  minimumPasswordComplexity: number;
  serverErrors: ServerError[];
  confirmServerErrors: ServerError[];
}> = ({ minimumPasswordComplexity, serverErrors, confirmServerErrors }) => {
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
      </Form.Field>
    </>
  );
};

const PasswordRegisterForm: React.FC<{ data: Data }> = ({ data }) => {
  const { t } = useTranslation();
  const { fields, errors: formErrors } = data.form;
  // `null` until the widget has mounted and told us it is ready; `true` right
  // away when there is no captcha to solve.
  const [captchaValid, setCaptchaValid] = useState<boolean | null>(
    data.captchaConfig ? null : true,
  );
  const [captchaError, setCaptchaError] = useState<string | null>(null);

  const onCaptchaValidChange = useCallback((valid: boolean) => {
    setCaptchaValid(valid);
    if (valid) setCaptchaError(null);
  }, []);

  return (
    <Form.Root
      method="POST"
      onSubmit={(e) => {
        // Enter-to-submit bypasses the field's onBlur, so normalize here too.
        // Writing to the DOM is safe: the page navigates away right after.
        const username = e.currentTarget.elements.namedItem("username");
        if (username instanceof HTMLInputElement) {
          username.value = normalizeUsername(username.value);
        }

        if (captchaValid === null) {
          e.preventDefault();
          setCaptchaError(t("frontend.register.captcha_loading"));
          return;
        }

        if (!captchaValid) {
          e.preventDefault();
          setCaptchaError(t("frontend.register.captcha_incomplete"));
          return;
        }

        setCaptchaError(null);
      }}
    >
      <input type="hidden" name="csrf" value={data.csrfToken} />

      {formErrors.map((error, index) => (
        <div
          // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
          key={`${error.kind}-${index}`}
          role="alert"
          className="text-critical font-medium"
        >
          {formErrorMessage(t, error)}
        </div>
      ))}

      <UsernameField
        serverName={data.branding.server_name}
        defaultValue={fields.username?.value ?? ""}
        serverErrors={fields.username?.errors ?? []}
      />

      {data.features.password_registration_email_required && (
        <Form.Field name="email" serverInvalid={!!fields.email?.errors.length}>
          <Form.Label>{t("common.email_address")}</Form.Label>
          <Form.TextControl
            type="email"
            required
            autoComplete="email"
            defaultValue={fields.email?.value ?? ""}
          />
          <Form.ErrorMessage match="typeMismatch">
            {t("frontend.errors.invalid_email")}
          </Form.ErrorMessage>
          <Form.ErrorMessage match="valueMissing">
            {t("frontend.errors.field_required")}
          </Form.ErrorMessage>
          {fields.email?.errors.map((error, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
            <Form.ErrorMessage key={`${error.kind}-${index}`}>
              {fieldErrorMessage(t, error)}
            </Form.ErrorMessage>
          ))}
        </Form.Field>
      )}

      <PasswordFields
        minimumPasswordComplexity={data.features.minimum_password_complexity}
        serverErrors={fields.password?.errors ?? []}
        confirmServerErrors={fields.password_confirm?.errors ?? []}
      />

      {data.branding.tos_uri && (
        <Form.InlineField
          name="accept_terms"
          control={<Form.CheckboxControl required value="on" />}
          serverInvalid={!!fields.accept_terms?.errors.length}
        >
          <Form.Label>
            <Trans
              i18nKey="frontend.register.terms_of_service"
              components={{
                a: (
                  // biome-ignore lint/a11y/useAnchorContent: content filled by Trans
                  <a
                    href={data.branding.tos_uri}
                    target="_blank"
                    rel="noreferrer"
                    className="cpd-link"
                    data-kind="primary"
                  />
                ),
              }}
            />
          </Form.Label>
          <Form.ErrorMessage match="valueMissing">
            {t("frontend.errors.field_required")}
          </Form.ErrorMessage>
          {fields.accept_terms?.errors.map((error, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
            <Form.ErrorMessage key={`${error.kind}-${index}`}>
              {fieldErrorMessage(t, error)}
            </Form.ErrorMessage>
          ))}
        </Form.InlineField>
      )}

      <CaptchaSection
        config={data.captchaConfig}
        onValidChange={onCaptchaValidChange}
      />

      {captchaError && (
        <div role="alert" className="text-critical font-medium">
          {captchaError}
        </div>
      )}

      <Form.Submit>{t("action.continue")}</Form.Submit>

      <Button as="a" kind="tertiary" size="lg" href={data.loginLink}>
        {t("frontend.register.call_to_login")}
      </Button>
    </Form.Root>
  );
};

void mountIsland({
  id: "password-register-form",
  schema,
  queryClient,
  children: (data) => <PasswordRegisterForm data={data} />,
});
