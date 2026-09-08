// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// This is taken from the swagger-ui/dist/oauth2-redirect.html file

interface SwaggerUIRedirectOauth2 {
  state?: string;
  redirectUrl: string;
  auth: {
    name: string;
    code?: string;
    schema: { get(key: string): string };
  };
  errCb: (error: {
    authId: string;
    source: string;
    level: string;
    message: string;
  }) => void;
  callback: (result: {
    auth: SwaggerUIRedirectOauth2["auth"];
    redirectUrl: string;
    token?: unknown;
    isValid?: boolean;
  }) => void;
}

interface RedirectOpener extends Window {
  swaggerUIRedirectOauth2: SwaggerUIRedirectOauth2;
}

const oauth2 = (window.opener as RedirectOpener).swaggerUIRedirectOauth2;
const sentState = oauth2.state;
const redirectUrl = oauth2.redirectUrl;

let qpString: string;
if (/code|token|error/.test(window.location.hash)) {
  qpString = window.location.hash.substring(1).replace("?", "&");
} else {
  qpString = location.search.substring(1);
}

const arr = qpString.split("&");
for (let i = 0; i < arr.length; i++) {
  arr[i] = `"${arr[i].replace("=", '":"')}"`;
}
const qp: Record<string, string> = qpString
  ? JSON.parse(`{${arr.join()}}`, (key, value) =>
      key === "" ? value : decodeURIComponent(value),
    )
  : {};

const isValid = qp.state === sentState;

if (
  (oauth2.auth.schema.get("flow") === "accessCode" ||
    oauth2.auth.schema.get("flow") === "authorizationCode" ||
    oauth2.auth.schema.get("flow") === "authorization_code") &&
  !oauth2.auth.code
) {
  if (!isValid) {
    oauth2.errCb({
      authId: oauth2.auth.name,
      source: "auth",
      level: "warning",
      message:
        "Authorization may be unsafe, passed state was changed in server. The passed state wasn't returned from auth server.",
    });
  }

  if (qp.code) {
    delete oauth2.state;
    oauth2.auth.code = qp.code;
    oauth2.callback({ auth: oauth2.auth, redirectUrl: redirectUrl });
  } else {
    let oauthErrorMsg: string | undefined;
    if (qp.error) {
      oauthErrorMsg = `[${qp.error}]: ${
        qp.error_description
          ? `${qp.error_description}. `
          : "no accessCode received from the server. "
      }${qp.error_uri ? `More info: ${qp.error_uri}` : ""}`;
    }

    oauth2.errCb({
      authId: oauth2.auth.name,
      source: "auth",
      level: "error",
      message:
        oauthErrorMsg ||
        "[Authorization failed]: no accessCode received from the server.",
    });
  }
} else {
  oauth2.callback({
    auth: oauth2.auth,
    token: qp,
    isValid: isValid,
    redirectUrl: redirectUrl,
  });
}
window.close();
