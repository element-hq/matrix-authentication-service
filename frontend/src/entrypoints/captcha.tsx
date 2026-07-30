// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// Entrypoint which mounts the React `Captcha` component as an inline
// "island" on server-rendered pages. The server templates emit a
// placeholder element carrying the CAPTCHA configuration:
//
//   <div data-captcha-service="…" data-captcha-site-key="…"></div>
//
// and include this entrypoint, which mounts the widget onto every such
// element. This is the pattern we intend to use for progressively
// enhancing server-rendered pages with React components.

import { StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import * as v from "valibot";
import { Captcha, CaptchaPlaceholder } from "../components/Captcha";

const schema = v.object({
  captchaService: v.picklist([
    "recaptcha_v2",
    "cloudflare_turnstile",
    "hcaptcha",
  ]),
  captchaSiteKey: v.string(),
});

for (const node of document.querySelectorAll<HTMLElement>(
  "[data-captcha-service]",
)) {
  const config = v.parse(schema, node.dataset);
  createRoot(node).render(
    <StrictMode>
      <Suspense fallback={<CaptchaPlaceholder />}>
        <Captcha
          config={{
            service: config.captchaService,
            site_key: config.captchaSiteKey,
          }}
        />
      </Suspense>
    </StrictMode>,
  );
}
