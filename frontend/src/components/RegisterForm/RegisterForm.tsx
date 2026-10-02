// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Button, Form, Link, Text } from "@vector-im/compound-web";
import { Suspense, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import {
  type FieldState,
  fieldErrorMessage,
  formErrorMessage,
  type Invite,
  type Provider,
  type ServerError,
} from "../../utils/registration";
import {
  Captcha,
  type CaptchaConfig,
  type CaptchaHandle,
  CaptchaPlaceholder,
} from "../Captcha";
import OrSeparator from "../OrSeparator";
import { providerLogo } from "../ProviderLogo";
import { PasswordFields, UsernameField } from "./RegisterFields";
import styles from "./RegisterForm.module.css";

/**
 * Each provider is a submit button of the enclosing form, so that whatever was
 * typed in the username field travels with the request which starts the
 * upstream flow.
 */
const ProviderButtons: React.FC<{ providers: Provider[] }> = ({
  providers,
}) => {
  const { t } = useTranslation();
  return (
    <>
      {providers.map((provider) => (
        <Button
          key={provider.id}
          type="submit"
          name="provider"
          value={provider.id}
          // The username is advisory on this path: don't hold the user back
          // over a field the upstream provider may well override
          formNoValidate
          kind="secondary"
          size="lg"
          Icon={providerLogo(provider.brand)}
        >
          {t("frontend.register.continue_with_provider", {
            provider: provider.name,
          })}
        </Button>
      ))}
    </>
  );
};

const ErrorAlert: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div role="alert" className="text-critical font-medium">
    {children}
  </div>
);

const LoginLink: React.FC<{ href: string }> = ({ href }) => {
  const { t } = useTranslation();
  return (
    <Button
      as="a"
      kind="tertiary"
      size="lg"
      href={href}
      className={styles.loginLink}
    >
      {t("frontend.register.call_to_login")}
    </Button>
  );
};

/**
 * With upstream providers on offer, the username comes first, so that it can
 * travel with a provider button as well as lead on to the password form.
 */
type Step = "username" | "password";

export const PasswordRegisterForm: React.FC<{
  csrfToken: string;
  serverName: string;
  tosUri?: string | null;
  emailRequired: boolean;
  minimumPasswordComplexity: number;
  captchaConfig?: CaptchaConfig;
  formErrors: ServerError[];
  fields: Partial<Record<string, FieldState>>;
  providers: Provider[];
  loginLink: string;
  invite?: Invite;
}> = ({
  csrfToken,
  serverName,
  tosUri,
  emailRequired,
  minimumPasswordComplexity,
  captchaConfig,
  formErrors,
  fields,
  providers,
  loginLink,
  invite,
}) => {
  const { t } = useTranslation();
  // A valid invite code may pin the identity the account is registered with,
  // and waive the password entirely
  const pinnedUsername = invite?.valid ? invite.username : null;
  const pinnedEmail = invite?.valid ? invite.email : null;
  const passwordless = invite?.valid === true && invite.passwordless;
  // The server reports a code it refused both in the mount data and as an
  // error on the `token` field, which has no control of its own to carry it
  const inviteInvalid =
    invite?.valid === false || (fields.token?.errors.length ?? 0) > 0;
  const showEmailField = !pinnedEmail && (emailRequired || passwordless);
  // `null` until the widget has mounted; the handle reports `valid: true`
  // straight away when there is no captcha to solve.
  const captchaRef = useRef<CaptchaHandle>(null);
  const [captchaError, setCaptchaError] = useState<string | null>(null);
  // Server errors from the last POST, dropped for each field as it is edited
  const [fieldErrors, setFieldErrors] = useState(() =>
    Object.fromEntries(
      Object.entries(fields).map(([name, field]) => [name, field?.errors]),
    ),
  );
  const serverErrors = (field: string): ServerError[] =>
    fieldErrors[field] ?? [];
  // A submission which came back with errors went through both steps already,
  // and an invite link goes straight to the form it may have pinned fields of
  const [initialStep] = useState<Step>(() =>
    providers.length > 0 &&
    !invite &&
    formErrors.length === 0 &&
    Object.values(fields).every((field) => !field?.errors.length)
      ? "username"
      : "password",
  );
  const [step, setStep] = useState(initialStep);
  // Only move the focus along when the user got here from the first step
  const advanced = initialStep === "username" && step === "password";

  return (
    <Form.Root
      method="POST"
      className="min-w-0"
      onChange={(e) => {
        // Typed as the form, but this is the input which changed
        const input: EventTarget = e.target;
        if (input instanceof HTMLInputElement && fieldErrors[input.name]) {
          const { [input.name]: _cleared, ...rest } = fieldErrors;
          setFieldErrors(rest);
        }
      }}
      onClearServerErrors={() => setFieldErrors({})}
      onKeyDown={(e) => {
        // Enter would otherwise submit the form with the first provider button
        if (
          step === "username" &&
          e.key === "Enter" &&
          e.target instanceof HTMLInputElement &&
          e.target.name === "username"
        ) {
          e.preventDefault();
          setStep("password");
        }
      }}
      onSubmit={(e) => {
        // A provider button submits the form as-is: let the browser POST it,
        // carrying the username along to the server, which starts the upstream
        // flow from there
        const { submitter } = e.nativeEvent as SubmitEvent;
        if (
          submitter instanceof HTMLButtonElement &&
          submitter.name === "provider"
        ) {
          return;
        }

        if (captchaRef.current === null) {
          e.preventDefault();
          setCaptchaError(t("frontend.register.captcha_loading"));
          return;
        }

        if (!captchaRef.current.valid) {
          e.preventDefault();
          setCaptchaError(t("frontend.register.captcha_incomplete"));
          return;
        }

        setCaptchaError(null);
      }}
    >
      <input type="hidden" name="csrf" value={csrfToken} />

      {/* The invite code the page was opened with, so that it survives a
          failed submission */}
      {fields.token?.value && (
        <input type="hidden" name="token" value={fields.token.value} />
      )}

      {inviteInvalid && (
        <ErrorAlert>{t("frontend.register.invite_invalid")}</ErrorAlert>
      )}

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

      {/* A pinned username is not the user's to pick, so it isn't shown */}
      {!pinnedUsername && (
        <UsernameField
          serverName={serverName}
          defaultValue={fields.username?.value ?? ""}
          serverErrors={serverErrors("username")}
        />
      )}

      {step === "password" && (
        <>
          {pinnedEmail && (
            <Text size="sm" className="text-secondary">
              {t("frontend.register.email_verification_notice", {
                email: pinnedEmail,
              })}
            </Text>
          )}

          {showEmailField && (
            <Form.Field
              name="email"
              serverInvalid={serverErrors("email").length > 0}
            >
              <Form.Label>{t("common.email_address")}</Form.Label>
              <Form.TextControl
                type="email"
                required
                autoComplete="email"
                defaultValue={fields.email?.value ?? ""}
                autoFocus={advanced}
              />
              <Form.ErrorMessage match="typeMismatch">
                {t("frontend.errors.invalid_email")}
              </Form.ErrorMessage>
              <Form.ErrorMessage match="valueMissing">
                {t("frontend.errors.field_required")}
              </Form.ErrorMessage>
              {serverErrors("email").map((error, index) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
                <Form.ErrorMessage key={`${error.kind}-${index}`}>
                  {fieldErrorMessage(t, error)}
                </Form.ErrorMessage>
              ))}
            </Form.Field>
          )}

          {passwordless ? (
            // The line about the pinned address already says a code is coming
            !pinnedEmail && (
              <Text size="sm" className="text-secondary">
                {t("frontend.register.passwordless_notice")}
              </Text>
            )
          ) : (
            <PasswordFields
              autoFocus={advanced && !showEmailField}
              minimumPasswordComplexity={minimumPasswordComplexity}
              serverErrors={serverErrors("password")}
              confirmServerErrors={serverErrors("password_confirm")}
            />
          )}

          {tosUri && (
            <Form.InlineField
              name="accept_terms"
              control={<Form.CheckboxControl required value="on" />}
              serverInvalid={serverErrors("accept_terms").length > 0}
            >
              <Form.Label>
                <Trans
                  i18nKey="frontend.register.terms_of_service"
                  components={{
                    a: <Link href={tosUri} target="_blank" />,
                  }}
                />
              </Form.Label>
              <Form.ErrorMessage match="valueMissing">
                {t("frontend.errors.field_required")}
              </Form.ErrorMessage>
              {serverErrors("accept_terms").map((error, index) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: the server error list is static
                <Form.ErrorMessage key={`${error.kind}-${index}`}>
                  {fieldErrorMessage(t, error)}
                </Form.ErrorMessage>
              ))}
            </Form.InlineField>
          )}

          <Suspense
            fallback={
              captchaConfig ? (
                <CaptchaPlaceholder service={captchaConfig.service} />
              ) : null
            }
          >
            <Captcha ref={captchaRef} config={captchaConfig} />
          </Suspense>

          {captchaError && (
            <div role="alert" className="text-critical font-medium">
              {captchaError}
            </div>
          )}

          {/* The form's first submit button, so that Enter in any of the fields
          registers rather than picking a provider */}
          <Form.Submit>
            {passwordless
              ? t("frontend.register.send_code")
              : t("action.continue")}
          </Form.Submit>

          {providers.length > 0 && (
            <Button
              type="button"
              kind="secondary"
              size="lg"
              onClick={() => setStep("username")}
            >
              {t("action.back")}
            </Button>
          )}
        </>
      )}

      {step === "username" && (
        <>
          <Button type="button" onClick={() => setStep("password")}>
            {emailRequired
              ? t("frontend.register.continue_with_email")
              : t("frontend.register.continue_with_password")}
          </Button>

          <OrSeparator>{t("frontend.register.or_separator")}</OrSeparator>
          <ProviderButtons providers={providers} />
        </>
      )}

      <LoginLink href={loginLink} />
    </Form.Root>
  );
};

/**
 * Without password registration there is nothing to fill in: the providers and
 * the sign-in link are the whole page. The form is still what carries the
 * provider buttons, so it stays, with nothing in it but the CSRF token.
 */
export const ProvidersOnlyForm: React.FC<{
  csrfToken: string;
  providers: Provider[];
  loginLink: string;
  inviteInvalid: boolean;
}> = ({ csrfToken, providers, loginLink, inviteInvalid }) => {
  const { t } = useTranslation();
  return (
    <Form.Root method="POST">
      <input type="hidden" name="csrf" value={csrfToken} />
      {inviteInvalid && (
        <ErrorAlert>{t("frontend.register.invite_invalid")}</ErrorAlert>
      )}
      <ProviderButtons providers={providers} />
      <LoginLink href={loginLink} />
    </Form.Root>
  );
};
