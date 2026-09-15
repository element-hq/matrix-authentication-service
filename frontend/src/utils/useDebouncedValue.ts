// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useEffect, useState } from "react";

/**
 * Returns `value` after it has stopped changing for `wait` milliseconds.
 */
export const useDebouncedValue = <T>(value: T, wait: number): T => {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timeout = setTimeout(() => setDebounced(value), wait);
    return () => clearTimeout(timeout);
  }, [value, wait]);

  return debounced;
};
