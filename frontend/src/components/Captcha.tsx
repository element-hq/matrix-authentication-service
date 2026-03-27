// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

/// <reference types="cloudflare-turnstile" />
/// <reference types="grecaptcha" />
/// <reference types="@hcaptcha/types"/>

import { forwardRef, memo, use, useImperativeHandle, useRef } from "react";

// Cache of script URLs to their load promises, so each script is only loaded
// once even if multiple components request it.
const scripts: Record<string, Promise<void>> = {};

// Counter used to generate unique global callback names for each script.
let i = 0;

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
 *     without injecting a second `<script>` tag.
 */
const loadScriptOnce = (script: string) => {
  if (!(script in scripts)) {
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    const scriptTag = document.createElement("script");
    scriptTag.defer = true;

    // Each script gets its own uniquely-named global callback so that
    // multiple different captcha scripts can coexist on the same page.
    const callbackName = `__onloadScript${i++}`;
    scriptTag.src = script.replace("__ONLOADFUNC__", callbackName);

    // Register the callback on `globalThis` so the captcha SDK can call it.
    // When invoked, it resolves the promise, unblocking any `use()` call.
    (globalThis as any)[callbackName] = resolve;

    // If the script fails to load (network error, blocked by CSP, etc.),
    // reject the promise so the error bubbles up to an error boundary.
    scriptTag.onerror = (cause) =>
      reject(new Error(`Failed to load script: ${script}`, { cause }));

    document.head.appendChild(scriptTag);
    scripts[script] = promise;
  }

  return scripts[script];
};

/** Load the Cloudflare Turnstile captcha SDK. Suspends until the SDK is ready. */
const useTurnstile = (): Turnstile.Turnstile => {
  use(
    loadScriptOnce(
      // render=explicit avoids any automatic rendering of the widget in the page
      "https://challenges.cloudflare.com/turnstile/v0/api.js?onload=__ONLOADFUNC__&render=explicit",
    ),
  );

  // The SDK injects itself in the window object
  return (globalThis as any).turnstile as Turnstile.Turnstile;
};

/** Load the Google ReCaptcha SDK. Suspends until the SDK is ready. */
const useRecaptcha = (): ReCaptchaV2.ReCaptcha => {
  use(
    loadScriptOnce(
      // render=explicit avoids any automatic rendering of the widget in the page
      "https://www.recaptcha.net/recaptcha/api.js?onload=__ONLOADFUNC__&render=explicit",
    ),
  );

  // The SDK injects itself in the window object
  return (globalThis as any).grecaptcha as ReCaptchaV2.ReCaptcha;
};

/** Load the hCaptcha SDK. Suspends until the SDK is ready. */
const useHCaptcha = (): HCaptcha => {
  use(
    loadScriptOnce(
      // render=explicit avoids any automatic rendering of the widget in the page
      // recaptchacompat=off avoids filling the 'grecaptcha' global and any conflict with ReCaptcha
      "https://js.hcaptcha.com/1/api.js?recaptchacompat=off&onload=__ONLOADFUNC__&render=explicit",
    ),
  );

  // The SDK injects itself in the window object
  return (globalThis as any).hcaptcha as HCaptcha;
};

const isDarkMediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

/** Handle exposed by captcha widgets via ref, to check validity before form submission. */
export type CaptchaHandle = {
  /** Whether the captcha has been successfully solved. */
  readonly valid: boolean;
};

export type CaptchaConfig = {
  service: "recaptcha_v2" | "cloudflare_turnstile" | "hcaptcha";
  site_key: string;
};

/** No captcha configured — always valid, renders nothing. */
const NoCaptcha = forwardRef<CaptchaHandle>((_props, ref) => {
  useImperativeHandle(ref, () => ({ valid: true }), []);
  return null;
});

/**
 * Dispatcher component that renders the right captcha widget based on config,
 * or nothing if no captcha is configured. In both cases it exposes a
 * {@link CaptchaHandle} via ref — when there is no captcha, `valid` is
 * always `true` so the form can submit freely.
 */
export const Captcha = memo(
  forwardRef<CaptchaHandle, { config?: CaptchaConfig | null }>(
    ({ config }, ref) => {
      if (!config) {
        return <NoCaptcha ref={ref} />;
      }

      switch (config.service) {
        case "recaptcha_v2":
          return <ReCaptchaWidget ref={ref} siteKey={config.site_key} />;
        case "cloudflare_turnstile":
          return <TurnstileWidget ref={ref} siteKey={config.site_key} />;
        case "hcaptcha":
          return <HCaptchaWidget ref={ref} siteKey={config.site_key} />;
      }
    },
  ),
);

export const ReCaptchaWidget = forwardRef<CaptchaHandle, { siteKey: string }>(
  ({ siteKey }, ref) => {
    const recaptcha = useRecaptcha();
    const valid = useRef(false);

    useImperativeHandle(
      ref,
      () => ({
        get valid() {
          return valid.current;
        },
      }),
      [],
    );

    return (
      <div
        ref={(node) => {
          if (node === null) return;

          const id = recaptcha.render(node, {
            sitekey: siteKey,
            theme: isDarkMediaQuery.matches ? "dark" : "light",
            callback: () => {
              valid.current = true;
            },
            "expired-callback": () => {
              valid.current = false;
            },
            "error-callback": () => {
              valid.current = false;
            },
          });

          return () => recaptcha.reset(id);
        }}
      />
    );
  },
);

export const TurnstileWidget = forwardRef<CaptchaHandle, { siteKey: string }>(
  ({ siteKey }, ref) => {
    const turnstile = useTurnstile();
    const valid = useRef(false);

    useImperativeHandle(
      ref,
      () => ({
        get valid() {
          return valid.current;
        },
      }),
      [],
    );

    return (
      <div
        ref={(node) => {
          if (node === null) return;

          const id = turnstile.render(node, {
            sitekey: siteKey,
            size: "flexible",
            callback: () => {
              valid.current = true;
            },
            "expired-callback": () => {
              valid.current = false;
            },
            "error-callback": () => {
              valid.current = false;
            },
          });

          return () => turnstile.remove(id ?? undefined);
        }}
      />
    );
  },
);

export const HCaptchaWidget = forwardRef<CaptchaHandle, { siteKey: string }>(
  ({ siteKey }, ref) => {
    const hcaptcha = useHCaptcha();
    const valid = useRef(false);

    useImperativeHandle(
      ref,
      () => ({
        get valid() {
          return valid.current;
        },
      }),
      [],
    );

    return (
      <div
        ref={(node) => {
          if (node === null) return;

          const id = hcaptcha.render(node, {
            sitekey: siteKey,
            theme: isDarkMediaQuery.matches ? "dark" : "light",
            callback: () => {
              valid.current = true;
            },
            "expired-callback": () => {
              valid.current = false;
            },
            "error-callback": () => {
              valid.current = false;
            },
          });

          return () => hcaptcha.remove(id);
        }}
      />
    );
  },
);
