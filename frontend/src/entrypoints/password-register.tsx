// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useDebouncedValue } from "@tanstack/react-pacer";
import { QueryClientProvider, useQuery } from "@tanstack/react-query";
import { Form, InlineSpinner, TooltipProvider } from "@vector-im/compound-web";
import {
  StrictMode,
  Suspense,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { createRoot } from "react-dom/client";
import { I18nextProvider, Trans, useTranslation } from "react-i18next";
import * as v from "valibot";
import { Captcha, type CaptchaHandle } from "../components/Captcha";
import ErrorBoundary from "../components/ErrorBoundary";
import LoadingScreen from "../components/LoadingScreen";
import PasswordCreationDoubleInput from "../components/PasswordCreationDoubleInput";
import { graphql } from "../gql";
import { graphqlRequest, queryClient } from "../graphql";
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
  features: v.object({
    password_registration: v.boolean(),
    password_registration_email_required: v.boolean(),
    password_login: v.boolean(),
    account_recovery: v.boolean(),
    login_with_email_allowed: v.boolean(),
    registration_token_required: v.boolean(),
  }),
  token: v.optional(v.nullable(v.string())),
  form: v.object({
    errors: v.array(formErrorSchema),
    fields: v.record(v.string(), fieldStateSchema),
  }),
});

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
    }
  }
`);

const REGISTRATION_TOKEN_QUERY = graphql(`
  query RegistrationToken($token: String!) {
    registrationToken(token: $token) {
      valid
      username
      email
    }
  }
`);

/** Info from a validated registration token, used to drive forced fields. */
type TokenInfo = {
  valid: boolean;
  username?: string | null;
  email?: string | null;
};

/**
 * Hook that validates a registration token via GraphQL.
 * Returns the token info and loading state.
 */
const useRegistrationToken = (token: string) => {
  const [debouncedToken] = useDebouncedValue(token, { wait: 500 });
  const enabled = debouncedToken.length > 0;

  const { data, isFetching } = useQuery({
    queryKey: ["registrationToken", debouncedToken],
    queryFn: ({ signal }) =>
      graphqlRequest({
        query: REGISTRATION_TOKEN_QUERY,
        variables: { token: debouncedToken },
        signal,
      }),
    enabled,
  });

  const isStale = token !== debouncedToken;
  const tokenInfo: TokenInfo | undefined = !isStale
    ? (data?.registrationToken ?? undefined)
    : undefined;
  const loading = enabled && (isFetching || isStale);

  return { tokenInfo, loading };
};

const TokenField: React.FC<{
  defaultValue: string;
  onTokenInfo: (info: TokenInfo | undefined) => void;
}> = ({ defaultValue, onTokenInfo }) => {
  const { t } = useTranslation();
  const [token, setToken] = useState(defaultValue);
  const { tokenInfo, loading } = useRegistrationToken(token);

  // Notify parent whenever token info changes
  useEffect(() => {
    onTokenInfo(tokenInfo);
  }, [tokenInfo, onTokenInfo]);

  return (
    <Form.Field
      name="token"
      serverInvalid={tokenInfo !== undefined && !tokenInfo.valid}
    >
      <Form.Label>{t("frontend.register.token_label")}</Form.Label>
      <Form.TextControl
        required
        autoComplete="off"
        defaultValue={defaultValue}
        onChange={(e) => setToken(e.target.value)}
      />

      {loading && (
        <Form.HelpMessage>
          <InlineSpinner />
          {t("frontend.register.token_checking")}
        </Form.HelpMessage>
      )}

      {tokenInfo?.valid && (
        <Form.SuccessMessage match="valid" forceMatch>
          {t("frontend.register.token_valid")}
        </Form.SuccessMessage>
      )}

      {tokenInfo && !tokenInfo.valid && (
        <Form.ErrorMessage match="badInput" forceMatch>
          {t("frontend.register.token_invalid")}
        </Form.ErrorMessage>
      )}

      <Form.ErrorMessage match="valueMissing">
        {t("frontend.errors.field_required")}
      </Form.ErrorMessage>
    </Form.Field>
  );
};

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

type Availability = {
  username: string;
  available: boolean;
  reason?: string | null;
};

const UsernameHelpMessage: React.FC<{
  normalized: string;
  serverName: string;
  loading: boolean;
  availability?: Availability;
}> = ({ normalized, serverName, loading, availability }) => {
  const { t } = useTranslation();
  const mxid = `@${normalized || "—"}:${serverName}`;

  if (loading) {
    return (
      <Form.HelpMessage>
        <InlineSpinner />
        {t("frontend.register.username_checking")}
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
  forcedUsername?: string | null;
}> = ({ serverName, defaultValue, serverErrors, forcedUsername }) => {
  const { t } = useTranslation();
  const fieldErrorMessage = useFieldErrorMessage();
  const isForced = !!forcedUsername;
  const [username, setUsername] = useState(defaultValue);
  // Track whether server errors have been cleared by the user editing
  const [serverCleared, setServerCleared] = useState(false);

  // When a forced username arrives from the token, use it
  const effective = isForced ? forcedUsername : username;
  const normalized = normalizeUsername(effective);
  const [debouncedUsername] = useDebouncedValue(normalized, { wait: 500 });

  // Live availability check — runs immediately for forced usernames,
  // otherwise only after the user has edited (server errors cleared)
  const checkable =
    isUsernameCheckable(debouncedUsername) && (isForced || serverCleared);
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
    (isForced || serverCleared) &&
    isUsernameCheckable(normalized) &&
    (isFetching || isStale);

  return (
    <Form.Field
      name="username"
      serverInvalid={
        unmappedServerErrors.length > 0 ||
        (availability !== undefined && !availability.available)
      }
    >
      <Form.Label>{t("common.username")}</Form.Label>
      <Form.TextControl
        key={isForced ? "forced" : "editable"}
        required
        readOnly={isForced}
        autoComplete="username"
        autoCorrect="off"
        autoCapitalize="none"
        defaultValue={isForced ? forcedUsername : defaultValue}
        style={{ textTransform: "lowercase" }}
        onChange={(e) => {
          if (isForced) return;
          setUsername(e.target.value);
          if (!serverCleared) setServerCleared(true);
        }}
        onBlur={(e) => {
          if (isForced) return;
          e.target.value = normalizeUsername(e.target.value);
          setUsername(e.target.value);
        }}
      />

      <UsernameHelpMessage
        normalized={normalized}
        serverName={serverName}
        loading={isLoading}
        availability={availability}
      />

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

      {unmappedServerErrors.map((error) => (
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
  const [tokenInfo, setTokenInfo] = useState<TokenInfo | undefined>(undefined);

  // Show the token field if a token was passed via URL or if tokens are required
  const showTokenField =
    data.features.registration_token_required || data.token != null;

  // Forced username/email from a validated token
  const forcedUsername = tokenInfo?.valid ? tokenInfo.username : undefined;
  const forcedEmail = tokenInfo?.valid ? tokenInfo.email : undefined;

  // Show email field if required by config OR forced by token
  const showEmail =
    data.features.password_registration_email_required || !!forcedEmail;

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

      {showTokenField && (
        <TokenField
          defaultValue={data.token ?? ""}
          onTokenInfo={setTokenInfo}
        />
      )}

      <UsernameField
        serverName={data.branding.server_name}
        defaultValue={fields.username?.value ?? ""}
        serverErrors={fields.username?.errors ?? []}
        forcedUsername={forcedUsername}
      />

      {showEmail && (
        <Form.Field name="email" serverInvalid={!!fields.email?.errors.length}>
          <Form.Label>{t("common.email_address")}</Form.Label>
          <Form.TextControl
            type="email"
            required
            readOnly={!!forcedEmail}
            autoComplete="email"
            defaultValue={forcedEmail ?? fields.email?.value ?? ""}
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
      )}

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
