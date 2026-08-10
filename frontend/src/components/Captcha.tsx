// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

/// <reference types="cloudflare-turnstile" />
/// <reference types="grecaptcha" />
/// <reference types="@hcaptcha/types"/>

import { Button } from "@vector-im/compound-web";
import {
  Component,
  Fragment,
  type ReactNode,
  Suspense,
  use,
  useCallback,
  useEffect,
  useRef,
} from "react";
import { useTranslation } from "react-i18next";

export type CaptchaService =
  | "recaptcha_v2"
  | "cloudflare_turnstile"
  | "hcaptcha";

export type CaptchaConfig = {
  service: CaptchaService;
  site_key: string;
};

// Cache of script URLs to their load promises, so each script is only loaded
// once even if multiple components request it.
const scripts = new Map<string, Promise<void>>();

// Counter used to generate unique global callback names for each script.
let scriptCounter = 0;

// Some providers fail silently: the script loads but its onload callback never
// fires. Reject rather than suspend forever.
const SETTLE_TIMEOUT = 20_000;

/**
 * Load an external script exactly once, returning a promise that resolves when
 * the script's onload callback fires.
 *
 * How it works:
 *  1. On the first call for a given URL, it creates a `<script>` tag and
 *     appends it to `<head>`.
 *  2. The URL must contain the placeholder `__ONLOADFUNC__`, which gets
 *     replaced with a unique global function name (e.g. `__onloadScript0`).
 *     Captcha providers all support an `onload=<funcName>` query parameter
 *     that calls the named function once the SDK is ready.
 *  3. That global function is wired to resolve the promise, so callers can
 *     `await` (or React `use()`) the returned promise to suspend until the
 *     SDK is available.
 *  4. The promise is cached in `scripts` by URL, so subsequent calls with
 *     the same URL return the already-resolved (or still-pending) promise
 *     without injecting a second `<script>` tag. A *failed* load is evicted
 *     from the cache, together with its `<script>` tag, so that retrying
 *     re-attempts the request instead of replaying the same rejection.
 */
const loadScriptOnce = (script: string): Promise<void> => {
  const cached = scripts.get(script);
  if (cached) return cached;

  const scriptTag = document.createElement("script");
  scriptTag.defer = true;

  // Each script gets its own uniquely-named global callback so that
  // multiple different captcha scripts can coexist on the same page.
  const callbackName = `__onloadScript${scriptCounter++}`;
  scriptTag.src = script.replace("__ONLOADFUNC__", callbackName);

  const promise = new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`Timed out loading script: ${script}`)),
      SETTLE_TIMEOUT,
    );

    // Register the callback on `globalThis` so the captcha SDK can call it.
    // When invoked, it resolves the promise, unblocking any `use()` call.
    // biome-ignore lint/suspicious/noExplicitAny: We explicitly add random properties to `globalThis`
    (globalThis as any)[callbackName] = () => {
      clearTimeout(timeout);
      resolve();
    };

    // If the script fails to load (network error, blocked by CSP, etc.),
    // reject the promise so the error bubbles up to an error boundary.
    scriptTag.onerror = (cause) => {
      clearTimeout(timeout);
      reject(new Error(`Failed to load script: ${script}`, { cause }));
    };
  });

  promise.catch(() => {
    scripts.delete(script);
    scriptTag.remove();
    // biome-ignore lint/suspicious/noExplicitAny: mirrors the assignment above
    delete (globalThis as any)[callbackName];
  });

  document.head.appendChild(scriptTag);
  scripts.set(script, promise);
  return promise;
};

// Evaluated lazily so importing this module doesn't require a DOM
const prefersDark = () =>
  window.matchMedia("(prefers-color-scheme: dark)").matches;

/** Callbacks a provider wires into its widget to report solve state. */
type WidgetCallbacks = {
  onSolved: () => void;
  onUnsolved: () => void;
};

/**
 * Everything that differs between captcha providers: which SDK to load, how to
 * reach it once loaded, and how to render and tear down a widget.
 */
type Provider<Api, Id> = {
  /** SDK URL, with `__ONLOADFUNC__` standing in for the global callback name. */
  readonly scriptUrl: string;
  /** Reads the SDK off `globalThis`; only valid once `scriptUrl` has loaded. */
  readonly getApi: () => Api;
  readonly render: (
    api: Api,
    node: HTMLElement,
    siteKey: string,
    callbacks: WidgetCallbacks,
  ) => Id;
  readonly remove: (api: Api, id: Id) => void;
  /** Rendered height of the widget, used to reserve space while loading. */
  readonly placeholderHeight: number;
};

const RECAPTCHA: Provider<ReCaptchaV2.ReCaptcha, number> = {
  // render=explicit avoids any automatic rendering of the widget in the page
  scriptUrl:
    "https://www.recaptcha.net/recaptcha/api.js?onload=__ONLOADFUNC__&render=explicit",
  // The SDK injects itself in the window object
  // biome-ignore lint/suspicious/noExplicitAny: We can't really typecheck this
  getApi: () => (globalThis as any).grecaptcha as ReCaptchaV2.ReCaptcha,
  render: (api, node, siteKey, { onSolved, onUnsolved }) =>
    api.render(node, {
      sitekey: siteKey,
      theme: prefersDark() ? "dark" : "light",
      callback: onSolved,
      "expired-callback": onUnsolved,
      "error-callback": onUnsolved,
    }),
  // grecaptcha has no remove(): reset() clears the state but leaves the
  // injected DOM behind — the widget component clears the container.
  remove: (api, id) => api.reset(id),
  placeholderHeight: 78,
};

const TURNSTILE: Provider<Turnstile.Turnstile, string | undefined> = {
  // render=explicit avoids any automatic rendering of the widget in the page
  scriptUrl:
    "https://challenges.cloudflare.com/turnstile/v0/api.js?onload=__ONLOADFUNC__&render=explicit",
  // The SDK injects itself in the window object
  // biome-ignore lint/suspicious/noExplicitAny: We can't really typecheck this
  getApi: () => (globalThis as any).turnstile as Turnstile.Turnstile,
  render: (api, node, siteKey, { onSolved, onUnsolved }) =>
    api.render(node, {
      sitekey: siteKey,
      size: "flexible",
      callback: onSolved,
      "expired-callback": onUnsolved,
      "error-callback": onUnsolved,
    }) ?? undefined,
  remove: (api, id) => api.remove(id),
  placeholderHeight: 65,
};

const HCAPTCHA: Provider<HCaptcha, string> = {
  // render=explicit avoids any automatic rendering of the widget in the page
  // recaptchacompat=off avoids filling the 'grecaptcha' global and any conflict with ReCaptcha
  scriptUrl:
    "https://js.hcaptcha.com/1/api.js?recaptchacompat=off&onload=__ONLOADFUNC__&render=explicit",
  // The SDK injects itself in the window object
  // biome-ignore lint/suspicious/noExplicitAny: We can't really typecheck this
  getApi: () => (globalThis as any).hcaptcha as HCaptcha,
  render: (api, node, siteKey, { onSolved, onUnsolved }) =>
    api.render(node, {
      sitekey: siteKey,
      theme: prefersDark() ? "dark" : "light",
      callback: onSolved,
      "expired-callback": onUnsolved,
      "error-callback": onUnsolved,
    }),
  remove: (api, id) => api.remove(id),
  placeholderHeight: 78,
};

const PROVIDERS = {
  recaptcha_v2: RECAPTCHA,
  cloudflare_turnstile: TURNSTILE,
  hcaptcha: HCAPTCHA,
};

/** Height used when the provider is unknown, so the layout still settles. */
const DEFAULT_PLACEHOLDER_HEIGHT = 78;

/** Height the widget of a given provider will occupy once rendered. */
export const captchaPlaceholderHeight = (service?: CaptchaService): number =>
  (service ? PROVIDERS[service]?.placeholderHeight : undefined) ??
  DEFAULT_PLACEHOLDER_HEIGHT;

/** Fixed-height placeholder to reserve the widget's space while the provider SDK loads. */
export const CaptchaPlaceholder: React.FC<{ height?: number }> = ({
  height = DEFAULT_PLACEHOLDER_HEIGHT,
}) => (
  <div
    className="w-full rounded bg-[var(--cpd-color-bg-subtle-secondary)]"
    style={{ height: `${height}px` }}
  />
);

const CaptchaWidget = <Api, Id>({
  provider,
  siteKey,
  onValidChange,
}: {
  provider: Provider<Api, Id>;
  siteKey: string;
  onValidChange?: (valid: boolean) => void;
}): React.ReactElement => {
  use(loadScriptOnce(provider.scriptUrl));
  const api = provider.getApi();

  // Kept in a ref so that a new `onValidChange` identity doesn't tear down and
  // re-render the widget, which would throw away an already-solved captcha.
  const onValidChangeRef = useRef(onValidChange);
  useEffect(() => {
    onValidChangeRef.current = onValidChange;
  });

  // React re-runs a callback ref's cleanup and setup whenever its identity
  // changes, so it has to stay stable across re-renders. React 19 never calls
  // a ref that returns a cleanup function with `null`, hence no null check.
  const ref = useCallback(
    (node: HTMLDivElement) => {
      const signal = (valid: boolean) => onValidChangeRef.current?.(valid);
      // The widget being mounted is what tells the form the SDK is ready
      signal(false);

      const id = provider.render(api, node, siteKey, {
        onSolved: () => signal(true),
        onUnsolved: () => signal(false),
      });

      return () => {
        provider.remove(api, id);
        // grecaptcha leaves its DOM behind; clearing is harmless for the others
        node.replaceChildren();
      };
    },
    [api, provider, siteKey],
  );

  return <div ref={ref} />;
};

/**
 * Renders the captcha widget for the given config, or nothing when no captcha
 * is configured. Suspends while the provider SDK loads, and throws if it fails
 * to load — use {@link CaptchaSection} to get the matching Suspense and error
 * boundaries.
 */
export const Captcha: React.FC<{
  config?: CaptchaConfig | null;
  onValidChange?: (valid: boolean) => void;
}> = ({ config, onValidChange }) => {
  // Dispatching per-service (rather than indexing `PROVIDERS` with the union)
  // is what keeps each provider's API and widget id types tied together.
  switch (config?.service) {
    case undefined:
      return null;
    case "recaptcha_v2":
      return (
        <CaptchaWidget
          provider={RECAPTCHA}
          siteKey={config.site_key}
          onValidChange={onValidChange}
        />
      );
    case "cloudflare_turnstile":
      return (
        <CaptchaWidget
          provider={TURNSTILE}
          siteKey={config.site_key}
          onValidChange={onValidChange}
        />
      );
    case "hcaptcha":
      return (
        <CaptchaWidget
          provider={HCAPTCHA}
          siteKey={config.site_key}
          onValidChange={onValidChange}
        />
      );
  }
};

/** Inline fallback shown when the provider SDK can't be loaded. */
export const CaptchaLoadError: React.FC<{ onRetry: () => void }> = ({
  onRetry,
}) => {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col items-start gap-2">
      <p className="text-critical font-medium">
        {t("frontend.captcha.load_failed")}
      </p>
      <Button kind="secondary" size="md" onClick={onRetry}>
        {t("action.try_again")}
      </Button>
    </div>
  );
};

/**
 * Error boundary local to the captcha, so that a provider SDK failing to load
 * doesn't take the surrounding form down with it.
 */
class CaptchaErrorBoundary extends Component<
  { children: ReactNode },
  { error?: Error; attempt: number }
> {
  public constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { attempt: 0 };
  }

  public static getDerivedStateFromError(error: Error): { error: Error } {
    return { error };
  }

  public componentDidCatch(error: Error): void {
    console.error("Failed to load the CAPTCHA", error);
  }

  private readonly retry = (): void =>
    // Bumping `attempt` remounts the subtree; the failed script promise has
    // been evicted from the cache, so the load is genuinely re-attempted.
    this.setState(({ attempt }) => ({
      error: undefined,
      attempt: attempt + 1,
    }));

  public render(): ReactNode {
    if (this.state.error) {
      return <CaptchaLoadError onRetry={this.retry} />;
    }

    return <Fragment key={this.state.attempt}>{this.props.children}</Fragment>;
  }
}

/**
 * The captcha, wrapped in its own Suspense and error boundaries: it reserves
 * the widget's height while the SDK loads and degrades to an inline retry
 * message if the SDK never arrives.
 */
export const CaptchaSection: React.FC<{
  config?: CaptchaConfig | null;
  onValidChange?: (valid: boolean) => void;
}> = ({ config, onValidChange }) => {
  if (!config) return null;

  return (
    <CaptchaErrorBoundary>
      <Suspense
        fallback={
          <CaptchaPlaceholder
            height={captchaPlaceholderHeight(config.service)}
          />
        }
      >
        <Captcha config={config} onValidChange={onValidChange} />
      </Suspense>
    </CaptchaErrorBoundary>
  );
};
