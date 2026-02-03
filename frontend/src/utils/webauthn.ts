// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

const b64urlDecode = (b64: string) =>
  Uint8Array.from(
    atob(b64.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.codePointAt(0) as number,
  );
const b64urlEncode = (buf: ArrayBuffer) =>
  btoa(Array.from(new Uint8Array(buf), (b) => String.fromCodePoint(b)).join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

// TS doesn't know AuthenticatorAttestationResponseJSON and AuthenticatorAssertionResponseJSON yet
type AuthenticatorAttestationResponseJSON = {
  clientDataJSON: Base64URLString;
  authenticatorData: Base64URLString;
  transports: string[];
  publicKey?: Base64URLString;
  publicKeyAlgorithm: COSEAlgorithmIdentifier;
  attestationObject: Base64URLString;
};

type AuthenticatorAssertionResponseJSON = {
  clientDataJSON: Base64URLString;
  authenticatorData: Base64URLString;
  signature: Base64URLString;
  userHandle?: Base64URLString;
};

// Polyfills for parse*FromJSON utils which aren't stable yet
if (typeof window !== "undefined" && window.PublicKeyCredential) {
  if (!window.PublicKeyCredential.parseCreationOptionsFromJSON) {
    window.PublicKeyCredential.parseCreationOptionsFromJSON = (options) =>
      ({
        ...options,
        user: {
          ...options.user,
          id: b64urlDecode(options.user.id),
        },
        challenge: b64urlDecode(options.challenge),
        excludeCredentials: options.excludeCredentials?.map((c) => ({
          ...c,
          id: b64urlDecode,
        })),
      }) as PublicKeyCredentialCreationOptions;
  }

  if (!window.PublicKeyCredential.parseRequestOptionsFromJSON) {
    window.PublicKeyCredential.parseRequestOptionsFromJSON = (options) =>
      ({
        ...options,
        challenge: b64urlDecode(options.challenge),
        allowCredentials: options.allowCredentials?.map((c) => ({
          ...c,
          id: b64urlDecode,
        })),
      }) as PublicKeyCredentialRequestOptions;
  }
}

export function checkSupport(): boolean {
  return !!window?.PublicKeyCredential;
}

export async function performRegistration(options: string): Promise<string> {
  const result = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(
      JSON.parse(options),
    ),
  });
  if (result === null) throw new Error("No credential returned");
  if (result.type !== "public-key" || !(result instanceof PublicKeyCredential))
    throw new Error("Bad credential type");

  try {
    if (result.toJSON) {
      // In some cases, this call will fail if the browser/extension
      // implementation is bad
      const json = result.toJSON();
      return JSON.stringify(json);
    }
  } catch (error) {
    console.warn(
      "Failed to use native PublicKeyCredential.toJSON, using fallback",
      error,
    );
  }

  if (!(result.response instanceof AuthenticatorAttestationResponse))
    throw new Error("Invalid response type");

  const publicKey = result.response.getPublicKey();
  if (publicKey === null) throw new Error("No public key returned");

  const json = {
    type: result.type,
    id: result.id,
    rawId: b64urlEncode(result.rawId),
    authenticatorAttachment: result.authenticatorAttachment,
    clientExtensionResults: result.getClientExtensionResults(),
    response: {
      attestationObject: b64urlEncode(result.response.attestationObject),
      authenticatorData: b64urlEncode(result.response.getAuthenticatorData()),
      clientDataJSON: b64urlEncode(result.response.clientDataJSON),
      publicKey: b64urlEncode(publicKey),
      publicKeyAlgorithm: result.response.getPublicKeyAlgorithm(),
      transports: result.response.getTransports(),
    } satisfies AuthenticatorAttestationResponseJSON,
  };

  return JSON.stringify(json);
}

export async function performAuthentication(
  options: PublicKeyCredentialRequestOptionsJSON,
  mediation: CredentialMediationRequirement,
  signal?: AbortSignal,
): Promise<string> {
  const result = await navigator.credentials.get({
    mediation,
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
    signal,
  });

  if (result === null) throw new Error("No credential returned");
  if (result.type !== "public-key" || !(result instanceof PublicKeyCredential))
    throw new Error("Bad credential type");

  try {
    if (result.toJSON) {
      // In some cases, this call will fail if the browser/extension
      // implementation is bad
      const json = result.toJSON();
      return JSON.stringify(json);
    }
  } catch (error) {
    console.warn(
      "Failed to use native PublicKeyCredential.toJSON, using fallback",
      error,
    );
  }

  if (!(result.response instanceof AuthenticatorAssertionResponse))
    throw new Error("Invalid response type");

  const json = {
    clientExtensionResults: result.getClientExtensionResults(),
    id: result.id,
    rawId: b64urlEncode(result.rawId),
    type: result.type,
    authenticatorAttachment: result.authenticatorAttachment,
    response: {
      authenticatorData: b64urlEncode(result.response.authenticatorData),
      clientDataJSON: b64urlEncode(result.response.clientDataJSON),
      signature: b64urlEncode(result.response.signature),
      userHandle: result.response.userHandle
        ? b64urlEncode(result.response.userHandle)
        : undefined,
    } satisfies AuthenticatorAssertionResponseJSON,
  };

  return JSON.stringify(json);
}
