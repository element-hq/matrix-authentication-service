// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

/**
 * Simplify a URL by removing the protocol, search params and hash.
 *
 * @param url The URL to simplify
 * @returns The simplified URL
 */
const simplifyUrl = (url: string): string => {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (_e) {
    // Not a valid URL, return the original
    return url;
  }

  // Clear out the search params and hash
  parsed.search = "";
  parsed.hash = "";

  if (parsed.protocol === "https:") {
    return parsed.hostname;
  }

  // Return the simplified URL
  return parsed.toString();
};

export default simplifyUrl;
