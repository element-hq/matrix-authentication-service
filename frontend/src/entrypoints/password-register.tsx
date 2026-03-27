// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { QueryClientProvider } from "@tanstack/react-query";
import { Form, TooltipProvider } from "@vector-im/compound-web";
import { StrictMode, Suspense, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider, Trans, useTranslation } from "react-i18next";
import * as v from "valibot";
import { Captcha, type CaptchaHandle } from "../components/Captcha";
import ErrorBoundary from "../components/ErrorBoundary";
import LoadingScreen from "../components/LoadingScreen";
import PasswordCreationDoubleInput from "../components/PasswordCreationDoubleInput";
import { queryClient } from "../graphql";
import i18n, { setupI18n } from "../i18n";
import "./shared.css";

setupI18n();

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

const schema = v.object({
  csrf_token: v.string(),
  captcha_config: v.optional(
    v.nullable(
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
  branding: v.object({
    server_name: v.string(),
    policy_uri: v.optional(v.nullable(v.string())),
    tos_uri: v.optional(v.nullable(v.string())),
    imprint: v.optional(v.nullable(v.string())),
  }),
  form: v.object({
    errors: v.array(formErrorSchema),
    fields: v.record(v.string(), fieldStateSchema),
  }),
});

type FieldError = v.InferOutput<typeof fieldErrorSchema>;
type FormError = v.InferOutput<typeof formErrorSchema>;

// Valid Matrix localpart: lowercase ascii, digits, and a few special chars
const VALID_LOCALPART_RE = /^[a-z0-9._=/+-]+$/;

const CaptchaPlaceholder: React.FC = () => (
  <div className="w-full h-[71px] rounded bg-[var(--cpd-color-bg-subtle-secondary)]" />
);

const el = document.getElementById("password-register-form") as HTMLElement;
const data = v.parse(schema, (window as any).RENDER_DATA);

/**
 * Map a server-side field error to a translated error message.
 */
const useFieldErrorMessage = () => {
  const { t } = useTranslation();
  return (error: FieldError): string => {
    switch (error.kind) {
      case "required":
        return t("frontend.errors.field_required");
      case "exists":
        return t("frontend.errors.username_taken");
      case "password_mismatch":
        return t("frontend.errors.password_mismatch");
      case "policy":
        // Policy errors may have a well-known code with a translation
        // The server sends codes like "username-invalid-chars", "username-too-short", etc.
        // Fall back to the server-provided message
        return error.message || t("frontend.errors.field_required");
      default:
        return error.message || t("frontend.errors.field_required");
    }
  };
};

/**
 * Map a server-side form error to a translated error message.
 */
const useFormErrorMessage = () => {
  const { t } = useTranslation();
  return (error: FormError): string => {
    switch (error.kind) {
      case "captcha":
        return t("frontend.errors.captcha");
      case "rate_limit_exceeded":
        return t("frontend.errors.rate_limit_exceeded");
      case "password_mismatch":
        return t("frontend.errors.password_mismatch");
      case "policy":
        return error.message || "";
      default:
        return "";
    }
  };
};

const UsernameField: React.FC<{
  serverName: string;
  defaultValue: string;
  serverErrors: FieldError[];
}> = ({ serverName, defaultValue, serverErrors }) => {
  const { t } = useTranslation();
  const fieldErrorMessage = useFieldErrorMessage();
  const [username, setUsername] = useState(defaultValue);

  return (
    <Form.Field name="username" serverInvalid={!!serverErrors.length}>
      <Form.Label>{t("common.username")}</Form.Label>
      <Form.TextControl
        required
        autoComplete="username"
        autoCorrect="off"
        autoCapitalize="none"
        defaultValue={defaultValue}
        style={{ textTransform: "lowercase" }}
        onChange={(e) => {
          setUsername(e.target.value);
        }}
        onBlur={(e) => {
          // Normalize the actual value on blur — CSS handles the visual lowercase
          e.target.value = e.target.value.trim().toLocaleLowerCase();
          setUsername(e.target.value);
        }}
      />
      <Form.HelpMessage>
        @{username.toLocaleLowerCase().trim() || "—"}:{serverName}
      </Form.HelpMessage>
      <Form.ErrorMessage match="valueMissing">
        {t("frontend.errors.field_required")}
      </Form.ErrorMessage>
      <Form.ErrorMessage
        match={(value) => {
          const normalized = value.trim().toLocaleLowerCase();
          return normalized.length > 0 && !VALID_LOCALPART_RE.test(normalized);
        }}
      >
        {t("frontend.errors.username_invalid")}
      </Form.ErrorMessage>
      {serverErrors.map((error) => (
        <Form.ErrorMessage key={error.kind}>
          {fieldErrorMessage(error)}
        </Form.ErrorMessage>
      ))}
    </Form.Field>
  );
};

const PasswordRegisterForm: React.FC = () => {
  const { t } = useTranslation();
  const captchaRef = useRef<CaptchaHandle>(null);
  const fieldErrorMessage = useFieldErrorMessage();
  const formErrorMessage = useFormErrorMessage();
  const { fields, errors: formErrors } = data.form;

  return (
    <Form.Root
      method="POST"
      onSubmit={(e) => {
        if (!captchaRef.current?.valid) {
          e.preventDefault();
        }
      }}
    >
      <input type="hidden" name="csrf" value={data.csrf_token} />

      {formErrors.map((error) => {
        const message = formErrorMessage(error);
        return message ? (
          <div key={error.kind} className="text-critical font-medium">
            {message}
          </div>
        ) : null;
      })}

      <UsernameField
        serverName={data.branding.server_name}
        defaultValue={fields.username?.value ?? ""}
        serverErrors={fields.username?.errors ?? []}
      />

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
        {fields.email?.errors.map((error) => (
          <Form.ErrorMessage key={error.kind}>
            {fieldErrorMessage(error)}
          </Form.ErrorMessage>
        ))}
      </Form.Field>

      <PasswordCreationDoubleInput
        minimumPasswordComplexity={3}
        forceShowNewPasswordInvalid={!!fields.password?.errors.length}
        passwordFieldName="password"
        passwordConfirmFieldName="password_confirm"
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
          {fields.accept_terms?.errors.map((error) => (
            <Form.ErrorMessage key={error.kind}>
              {fieldErrorMessage(error)}
            </Form.ErrorMessage>
          ))}
        </Form.InlineField>
      )}

      <Suspense fallback={<CaptchaPlaceholder />}>
        <Captcha ref={captchaRef} config={data.captcha_config} />
      </Suspense>

      <Form.Submit>{t("action.continue")}</Form.Submit>
    </Form.Root>
  );
};

createRoot(el).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ErrorBoundary>
        <TooltipProvider>
          <Suspense fallback={<LoadingScreen />}>
            <I18nextProvider i18n={i18n}>
              <PasswordRegisterForm />
            </I18nextProvider>
          </Suspense>
        </TooltipProvider>
      </ErrorBoundary>
    </QueryClientProvider>
  </StrictMode>,
);
