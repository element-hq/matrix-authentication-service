// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import "webauthn-polyfills"; // For the fromJSON and toJSON utils which aren't stable yet

export function checkSupport(): boolean {
  return !!window?.PublicKeyCredential;
}

export async function performRegistration(options: string): Promise<string> {
  const opts: { publicKey: PublicKeyCredentialCreationOptionsJSON } =
    JSON.parse(options);
  const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
    opts.publicKey,
  );

  const credential = await navigator.credentials.create({ publicKey });

  return JSON.stringify(credential);
}
