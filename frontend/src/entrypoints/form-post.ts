// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// Submit the form on the next tick, so the browser can paint the
// placeholder before navigating away.
setTimeout(() => {
  document.forms[0].submit();
}, 0);
