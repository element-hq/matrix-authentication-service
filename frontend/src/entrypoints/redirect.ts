// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// Navigate on the next tick so the browser can paint the placeholder before
// navigating away. The target URL is read from the visible link's `href`
// rather than being interpolated into this script.
const link = document.querySelector<HTMLAnchorElement>("#redirect-link");
if (link) {
  setTimeout(() => {
    window.location.replace(link.href);
  }, 0);
}
