// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Form } from "@vector-im/compound-web";
import { Suspense, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import * as v from "valibot";
import {
  Captcha,
  type CaptchaHandle,
  CaptchaPlaceholder,
} from "../components/Captcha";
import PasswordComplexityFeedback from "../components/PasswordComplexityFeedback";
import ProviderLogo, { hasProviderLogo } from "../components/ProviderLogo";
import { mountIsland } from "../utils/mountIsland";
import {
  fieldErrorMessage,
  formErrorMessage,
  normalizeUsername,
  type ServerError,
  serverErrorSchema,
  VALID_LOCALPART_RE,
} from "../utils/registration";
import "./shared.css";

const fieldStateSchema = v.object({
  value: v.optional(v.nullable(v.string())),
  errors: v.array(serverErrorSchema),
});

const providerSchema = v.object({
  /** Display name, already resolved server-side */
  name: v.string(),
  /** Raw `brand_name`; only the brands we have a logo for get an icon */
  brand: v.nullable(v.string()),
  /** Submitted back as the `provider` field of the form */
  id: v.string(),
});

type Provider = v.InferOutput<typeof providerSchema>;

// Parsed from the mount node's `data-*` attributes; structured values are
// JSON-encoded by the template.
const schema = v.object({
  csrfToken: v.string(),
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
      password_registration: v.boolean(),
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
  providers: v.pipe(v.string(), v.parseJson(), v.array(providerSchema)),
  /** Href for the "already have an account?" call to action */
  loginLink: v.string(),
});

type Data = v.InferOutput<typeof schema>;

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

  return (
    <Form.Field
      name="username"
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

/** Same look as the SSR `field.separator()` macro. */
const OrSeparator: React.FC = () => {
  const { t } = useTranslation();
  return (
    <div className="separator">
      <hr />
      <p>{t("frontend.register.or_separator")}</p>
      <hr />
    </div>
  );
};

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
        <button
          key={provider.id}
          type="submit"
          name="provider"
          value={provider.id}
          // The username is advisory on this path: don't hold the user back
          // over a field the upstream provider may well override
          formNoValidate
          className={
            hasProviderLogo(provider.brand)
              ? "cpd-button has-icon"
              : "cpd-button"
          }
          data-kind="secondary"
          data-size="lg"
        >
          <ProviderLogo brand={provider.brand} />
          {t("frontend.register.continue_with_provider", {
            provider: provider.name,
          })}
        </button>
      ))}
    </>
  );
};

const LoginLink: React.FC<{ href: string }> = ({ href }) => {
  const { t } = useTranslation();
  return (
    <a className="cpd-button" data-kind="tertiary" data-size="lg" href={href}>
      {t("frontend.register.call_to_login")}
    </a>
  );
};

const PasswordRegisterForm: React.FC<{ data: Data }> = ({ data }) => {
  const { t } = useTranslation();
  const { fields, errors: formErrors } = data.form;
  const { providers } = data;
  // `null` until the widget has mounted; the handle reports `valid: true`
  // straight away when there is no captcha to solve.
  const captchaRef = useRef<CaptchaHandle>(null);
  const [captchaError, setCaptchaError] = useState<string | null>(null);

  return (
    <Form.Root
      method="POST"
      className="cpd-form-root min-w-0"
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

        // Enter-to-submit bypasses the field's onBlur, so normalize here too.
        // Writing to the DOM is safe: the page navigates away right after.
        const username = e.currentTarget.elements.namedItem("username");
        if (username instanceof HTMLInputElement) {
          username.value = normalizeUsername(username.value);
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

      <Suspense
        fallback={
          data.captchaConfig ? (
            <CaptchaPlaceholder service={data.captchaConfig.service} />
          ) : null
        }
      >
        <Captcha ref={captchaRef} config={data.captchaConfig} />
      </Suspense>

      {captchaError && (
        <div role="alert" className="text-critical font-medium">
          {captchaError}
        </div>
      )}

      {/* The form's first submit button, so that Enter in any of the fields
          registers rather than picking a provider */}
      <Form.Submit>{t("action.continue")}</Form.Submit>

      {providers.length > 0 && (
        <>
          <OrSeparator />
          <ProviderButtons providers={providers} />
        </>
      )}

      <LoginLink href={data.loginLink} />
    </Form.Root>
  );
};

const RegisterPage: React.FC<{ data: Data }> = ({ data }) => {
  // Without password registration there is nothing to fill in: the providers
  // and the sign-in link are the whole page. The form is still what carries the
  // provider buttons, so it stays, with nothing in it but the CSRF token.
  if (!data.features.password_registration) {
    return (
      <form method="POST" className="cpd-form-root">
        <input type="hidden" name="csrf" value={data.csrfToken} />
        <ProviderButtons providers={data.providers} />
        <LoginLink href={data.loginLink} />
      </form>
    );
  }

  return <PasswordRegisterForm data={data} />;
};

void mountIsland({
  id: "register-form",
  schema,
  render: (data) => <RegisterPage data={data} />,
});
