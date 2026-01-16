/// <reference types="cloudflare-turnstile" />
/// <reference types="grecaptcha" />
/// <reference types="@hcaptcha/types"/>

import { use, useLayoutEffect, useRef } from "react";

const scripts: Record<string, Promise<void>> = {};

let i = 0;
const loadScriptOnce = (script: string) => {
  if (!(script in scripts)) {
    const { promise, resolve } = Promise.withResolvers<void>();
    const scriptTag = document.createElement("script");
    scriptTag.async = true;
    scriptTag.defer = true;
    const callbackName = `__onloadScript${i++}`;
    scriptTag.src = script.replace("__ONLOADFUNC__", callbackName);
    (globalThis as any)[callbackName] = resolve;
    document.head.appendChild(scriptTag);
    scripts[script] = promise;
  }

  return scripts[script];
};

const useTurnstile = (): Turnstile.Turnstile => {
  use(
    loadScriptOnce(
      "https://challenges.cloudflare.com/turnstile/v0/api.js?onload=__ONLOADFUNC__&render=explicit",
    ),
  );

  return (globalThis as any).turnstile as Turnstile.Turnstile;
};

const useRecaptcha = (): ReCaptchaV2.ReCaptcha => {
  use(
    loadScriptOnce(
      "https://www.google.com/recaptcha/api.js?onload=__ONLOADFUNC__&render=explicit",
    ),
  );

  return (globalThis as any).grecaptcha as ReCaptchaV2.ReCaptcha;
};

const useHCaptcha = (): HCaptcha => {
  use(
    loadScriptOnce(
      "https://js.hcaptcha.com/1/api.js?recaptchacompat=off&onload=__ONLOADFUNC__&render=explicit",
    ),
  );

  return (globalThis as any).hcaptcha as HCaptcha;
};

// Those are test keys
const RECAPTCHA_SITEKEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI";
const TURNSTILE_SITEKEY = "1x00000000000000000000AA";
const HCAPTCHA_SITEKEY = "10000000-ffff-ffff-ffff-000000000001";

export const ReCaptchaWidget = () => {
  const recaptcha = useRecaptcha();
  const container = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const current = container.current;
    const isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    if (current) {
      recaptcha.render(current, {
        sitekey: RECAPTCHA_SITEKEY,
        theme: isDark ? "dark" : "light",
      });
    }
  }, []);

  return <div ref={container} />;
};

export const TurnstileWidget = () => {
  const turnstile = useTurnstile();
  const container = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (container.current) {
      const id = turnstile.render(container.current, {
        sitekey: TURNSTILE_SITEKEY,
      });

      return () => turnstile.remove(id ?? undefined);
    }
  }, []);

  return <div ref={container} />;
};

export const HCaptchaWidget = () => {
  const hcaptcha = useHCaptcha();
  const container = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (container.current) {
      const isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      const id = hcaptcha.render(container.current, {
        sitekey: HCAPTCHA_SITEKEY,
        theme: isDark ? "dark" : "light",
      });

      return () => hcaptcha.remove(id);
    }
  }, []);

  return <div ref={container} />;
};
