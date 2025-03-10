// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// Polyfills for fromJSON and toJSON utils which aren't stable yet
if (typeof window !== "undefined" && window.PublicKeyCredential) {
  const b64urlDecode = (b64: string) =>
    Uint8Array.from(
      atob(b64.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.codePointAt(0) as number,
    );
  const b64urlEncode = (buf: ArrayBuffer) =>
    btoa(
      Array.from(new Uint8Array(buf), (b) => String.fromCodePoint(b)).join(""),
    )
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

  if (!window.PublicKeyCredential.prototype.toJSON) {
    window.PublicKeyCredential.prototype.toJSON = function () {
      const cred = {
        id: this.id,
        rawId: b64urlEncode(this.rawId),
        response: {
          clientDataJSON: b64urlEncode(this.response.clientDataJSON),
        },
        authenticatorAttachment: this.authenticatorAttachment,
        clientExtensionResults: this.getClientExtensionResults(),
        type: this.type,
      } as PublicKeyCredentialJSON;

      if (this.response instanceof window.AuthenticatorAttestationResponse) {
        const publicKey = this.response.getPublicKey();
        cred.response = {
          ...cred.response,
          authenticatorData: b64urlEncode(this.response.getAuthenticatorData()),
          transports: this.response.getTransports(),
          publicKey: publicKey ? b64urlEncode(publicKey) : null,
          publicKeyAlgorithm: this.response.getPublicKeyAlgorithm(),
          attestationObject: b64urlEncode(this.response.attestationObject),
        } as AuthenticatorAttestationResponseJSON;
      }

      if (this.response instanceof window.AuthenticatorAssertionResponse) {
        const userHandle = this.response.userHandle;
        cred.response = {
          ...cred.response,
          authenticatorData: b64urlEncode(this.response.authenticatorData),
          signature: b64urlEncode(this.response.signature),
          userHandle: userHandle ? b64urlEncode(userHandle) : null,
        } as AuthenticatorAssertionResponseJSON;
      }

      return cred;
    };
  }
}

export function checkSupport(): boolean {
  return !!window?.PublicKeyCredential;
}

export async function performRegistration(options: string): Promise<string> {
  const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
    JSON.parse(options),
  );

  const credential = await navigator.credentials.create({ publicKey });

  return JSON.stringify(credential);
}
