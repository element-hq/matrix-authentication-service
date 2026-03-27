// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import {
  QueryClient,
  QueryClientProvider,
  useQuery,
} from "@tanstack/react-query";
import {
  Button,
  Form,
  InlineSpinner,
  TooltipProvider,
} from "@vector-im/compound-web";
import { StrictMode, Suspense, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider, Trans, useTranslation } from "react-i18next";
import * as v from "valibot";
import {
  Captcha,
  type CaptchaHandle,
  CaptchaPlaceholder,
} from "../components/Captcha";
import ErrorBoundary from "../components/ErrorBoundary";
import PasswordCreationDoubleInput from "../components/PasswordCreationDoubleInput";
import { graphql } from "../gql";
import type { UsernameUnavailableReason } from "../gql/graphql";
import { graphqlRequest, setGraphqlEndpoint } from "../graphql";
import i18n, { setupI18n } from "../i18n";
import { useDebouncedValue } from "../utils/useDebouncedValue";
import "./shared.css";

const queryClient = new QueryClient();

const fieldErrorSchema = v.object({
  kind: v.string(),
  code: v.optional(v.nullable(v.string())),
  message: v.optional(v.string()),
});

const fieldStateSchema = v.object({
  value: v.optional(v.nullable(v.string())),
  errors: v.array(fieldErrorSchema),
});

const formErrorSchema = v.object({
  kind: v.string(),
  code: v.optional(v.nullable(v.string())),
  message: v.optional(v.string()),
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
      errors: v.array(formErrorSchema),
      fields: v.record(v.string(), fieldStateSchema),
    }),
  ),
});

type Data = v.InferOutput<typeof schema>;
type FieldError = v.InferOutput<typeof fieldErrorSchema>;
type FormError = v.InferOutput<typeof formErrorSchema>;

// Valid Matrix localpart: lowercase ascii, digits, and a few special chars
const VALID_LOCALPART_RE = /^[a-z0-9._=/+-]+$/;

const USERNAME_AVAILABLE_QUERY = graphql(`
  query UsernameAvailable($username: String!) {
    usernameAvailable(username: $username) {
      username
      available
      reason
      violationCodes
    }
  }
`);

const el = document.getElementById("password-register-form");
if (!el) throw new Error("password-register-form not found");

/**
 * Map a well-known policy violation code to a translated message, or
 * `undefined` if the code is unknown to this version of the frontend.
 */
const usePolicyCodeMessage = () => {
  const { t } = useTranslation();
  return (code: string): string | undefined => {
    switch (code) {
      case "username-too-short":
        return t("frontend.errors.username_too_short");
      case "username-too-long":
        return t("frontend.errors.username_too_long");
      case "username-invalid-chars":
        return t("frontend.errors.username_invalid_chars");
      case "username-all-numeric":
        return t("frontend.errors.username_all_numeric");
      case "username-banned":
        return t("frontend.errors.username_banned");
      case "username-not-allowed":
        return t("frontend.errors.username_not_allowed");
      case "email-domain-not-allowed":
        return t("frontend.errors.email_domain_not_allowed");
      case "email-domain-banned":
        return t("frontend.errors.email_domain_banned");
      case "email-not-allowed":
        return t("frontend.errors.email_not_allowed");
      case "email-banned":
        return t("frontend.errors.email_banned");
      case "password-too-weak":
        return t("frontend.password_strength.too_weak");
      default:
        return undefined;
    }
  };
};

/**
 * Map a server-side field error to a translated error message.
 */
const useFieldErrorMessage = () => {
  const { t } = useTranslation();
  const policyCodeMessage = usePolicyCodeMessage();
  return (error: FieldError): string => {
    switch (error.kind) {
      case "required":
        return t("frontend.errors.field_required");
      case "exists":
        return t("frontend.errors.username_taken");
      case "password_mismatch":
        return t("frontend.errors.password_mismatch");
      case "policy":
        return (
          (error.code ? policyCodeMessage(error.code) : undefined) ??
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
};

/**
 * Map a server-side form error to a translated error message.
 */
const useFormErrorMessage = () => {
  const { t } = useTranslation();
  const policyCodeMessage = usePolicyCodeMessage();
  return (error: FormError): string => {
    switch (error.kind) {
      case "captcha":
        return t("frontend.errors.captcha");
      case "rate_limit_exceeded":
        return t("frontend.errors.rate_limit_exceeded");
      case "password_mismatch":
        return t("frontend.errors.password_mismatch");
      case "policy":
        return (
          (error.code ? policyCodeMessage(error.code) : undefined) ??
          error.message ??
          t("frontend.errors.unspecified")
        );
      default:
        return error.message ?? t("frontend.errors.unspecified");
    }
  };
};

type Availability = {
  username: string;
  available: boolean;
  reason?: UsernameUnavailableReason | null;
  violationCodes?: string[] | null;
};

const UsernameHelpMessage: React.FC<{
  normalized: string;
  serverName: string;
  loading: boolean;
  availability?: Availability;
}> = ({ normalized, serverName, loading, availability }) => {
  const { t } = useTranslation();
  const policyCodeMessage = usePolicyCodeMessage();
  const mxid = `@${normalized || "—"}:${serverName}`;

  if (loading) {
    const checking = t("frontend.register.username_checking");
    return (
      <Form.HelpMessage>
        {/* The spinner carries the accessible name, so the live region doesn't
            announce the same text twice */}
        <InlineSpinner role="img" aria-label={checking} />
        <span aria-hidden="true">{checking}</span>
      </Form.HelpMessage>
    );
  }

  if (availability?.available) {
    return (
      <Form.SuccessMessage match="valid" forceMatch>
        {t("frontend.register.username_available", { mxid })}
      </Form.SuccessMessage>
    );
  }

  if (availability && !availability.available) {
    if (availability.reason === "INVALID") {
      const messages = (availability.violationCodes ?? [])
        .map(policyCodeMessage)
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
        {availability.reason === "RESERVED"
          ? t("frontend.register.username_reserved", { mxid })
          : t("frontend.register.username_taken", { mxid })}
      </Form.ErrorMessage>
    );
  }

  return <Form.HelpMessage>{mxid}</Form.HelpMessage>;
};

/** Normalize a username: trim and lowercase. */
const normalizeUsername = (value: string) => value.trim().toLocaleLowerCase();

/** Whether a normalized username is valid for a GraphQL availability check. */
const isUsernameCheckable = (normalized: string) =>
  normalized.length > 0 && VALID_LOCALPART_RE.test(normalized);

/**
 * Map server-side field errors to an initial availability state so that both
 * server POST errors and live GraphQL checks render through the same path.
 */
const serverErrorsToAvailability = (
  username: string,
  errors: FieldError[],
): Availability | undefined => {
  if (errors.length === 0) return undefined;
  // "exists" from the server means taken
  const isExists = errors.some((e) => e.kind === "exists");
  if (isExists) {
    return { username, available: false, reason: "TAKEN" };
  }
  // For other server errors (policy, etc.) we don't map to availability
  return undefined;
};

const UsernameField: React.FC<{
  serverName: string;
  defaultValue: string;
  serverErrors: FieldError[];
}> = ({ serverName, defaultValue, serverErrors }) => {
  const { t } = useTranslation();
  const fieldErrorMessage = useFieldErrorMessage();
  const [username, setUsername] = useState(defaultValue);
  // Track whether server errors have been cleared by the user editing
  const [serverCleared, setServerCleared] = useState(false);

  const normalized = normalizeUsername(username);
  const debouncedUsername = useDebouncedValue(normalized, 500);

  // Live availability check — only runs after the user has edited (server cleared)
  const checkable = isUsernameCheckable(debouncedUsername) && serverCleared;
  const { data, isFetching } = useQuery({
    queryKey: ["usernameAvailable", debouncedUsername],
    queryFn: ({ signal }) =>
      graphqlRequest({
        query: USERNAME_AVAILABLE_QUERY,
        variables: { username: debouncedUsername },
        signal,
      }),
    enabled: checkable,
  });

  const isStale = normalized !== debouncedUsername;
  const liveAvailability = !isStale ? data?.usernameAvailable : undefined;

  // Before the user edits, map server errors to an availability result
  // so both sources render through UsernameHelpMessage.
  const serverAvailability = !serverCleared
    ? serverErrorsToAvailability(normalized, serverErrors)
    : undefined;

  // Merge: server availability before edit, live availability after
  const availability = serverAvailability ?? liveAvailability;

  // Server errors that don't map to availability (e.g. policy violations)
  const unmappedServerErrors =
    !serverCleared && !serverAvailability ? serverErrors : [];

  const isLoading =
    serverCleared && isUsernameCheckable(normalized) && (isFetching || isStale);

  return (
    <Form.Field
      name="username"
      // Only actual POST-returned errors make the control invalid: flipping
      // this from the live check would steal the focus while typing
      serverInvalid={!serverCleared && serverErrors.length > 0}
    >
      <Form.Label>{t("common.username")}</Form.Label>
      <Form.TextControl
        required
        autoComplete="username"
        autoCorrect="off"
        autoCapitalize="none"
        defaultValue={defaultValue}
        onChange={(e) => {
          // Lowercase as the user types, so what is shown is what gets sent
          const value = e.target.value.toLocaleLowerCase();
          e.target.value = value;
          setUsername(value);
          if (!serverCleared) setServerCleared(true);
        }}
        onBlur={(e) => {
          e.target.value = normalizeUsername(e.target.value);
          setUsername(e.target.value);
        }}
      />

      <div aria-live="polite">
        <UsernameHelpMessage
          normalized={normalized}
          serverName={serverName}
          loading={isLoading}
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

      {unmappedServerErrors.map((error, index) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
        <Form.ErrorMessage key={`${error.kind}-${index}`}>
          {fieldErrorMessage(error)}
        </Form.ErrorMessage>
      ))}
    </Form.Field>
  );
};

const PasswordRegisterForm: React.FC<{ data: Data }> = ({ data }) => {
  const { t } = useTranslation();
  const captchaRef = useRef<CaptchaHandle>(null);
  const fieldErrorMessage = useFieldErrorMessage();
  const formErrorMessage = useFormErrorMessage();
  const [captchaError, setCaptchaError] = useState<string | null>(null);
  const { fields, errors: formErrors } = data.form;

  return (
    <Form.Root
      method="POST"
      onSubmit={(e) => {
        // Enter-to-submit bypasses the field's onBlur, so normalize here too
        const username = e.currentTarget.elements.namedItem("username");
        if (username instanceof HTMLInputElement) {
          username.value = normalizeUsername(username.value);
        }

        // `captchaRef` is null while the provider SDK is still loading
        if (!captchaRef.current?.valid) {
          e.preventDefault();
          setCaptchaError(t("frontend.register.captcha_incomplete"));
          return;
        }

        setCaptchaError(null);
      }}
    >
      <input type="hidden" name="csrf" value={data.csrfToken} />

      {formErrors.map((error, index) => {
        const message = formErrorMessage(error);
        return (
          <div
            // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
            key={`${error.kind}-${index}`}
            className="text-critical font-medium"
          >
            {message}
          </div>
        );
      })}

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
              {fieldErrorMessage(error)}
            </Form.ErrorMessage>
          ))}
        </Form.Field>
      )}

      <PasswordCreationDoubleInput
        minimumPasswordComplexity={data.features.minimum_password_complexity}
        forceShowNewPasswordInvalid={!!fields.password?.errors.length}
        passwordFieldName="password"
        passwordConfirmFieldName="password_confirm"
        label={t("frontend.register.password_label")}
        confirmLabel={t("frontend.register.password_confirm_label")}
        invalidPasswordMessage={t("frontend.register.password_invalid")}
      />

      {data.branding.tos_uri && (
        <Form.InlineField
          name="accept_terms"
          control={<Form.CheckboxControl required value="on" />}
          serverInvalid={!!fields.accept_terms?.errors.length}
        >
          <Form.Label>
            <Trans
              i18nKey="mas.register.terms_of_service"
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
              {fieldErrorMessage(error)}
            </Form.ErrorMessage>
          ))}
        </Form.InlineField>
      )}

      <Suspense fallback={<CaptchaPlaceholder />}>
        <Captcha ref={captchaRef} config={data.captchaConfig} />
      </Suspense>

      {captchaError && (
        <div className="text-critical font-medium">{captchaError}</div>
      )}

      <Form.Submit>{t("action.continue")}</Form.Submit>

      <Button as="a" kind="tertiary" size="lg" href={data.loginLink}>
        {t("frontend.register.call_to_login")}
      </Button>
    </Form.Root>
  );
};

/** Parses the mount node's dataset inside the error boundary. */
const Root: React.FC<{ dataset: DOMStringMap }> = ({ dataset }) => {
  const data = useMemo(() => {
    const data = v.parse(schema, dataset);
    // Set before any query runs, i.e. before the children render
    setGraphqlEndpoint(data.graphqlEndpoint);
    return data;
  }, [dataset]);

  return <PasswordRegisterForm data={data} />;
};

(async () => {
  await setupI18n();

  const root = createRoot(el);
  root.render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ErrorBoundary>
          <TooltipProvider>
            <I18nextProvider i18n={i18n}>
              <Root dataset={el.dataset} />
            </I18nextProvider>
          </TooltipProvider>
        </ErrorBoundary>
      </QueryClientProvider>
    </StrictMode>,
  );
})();
