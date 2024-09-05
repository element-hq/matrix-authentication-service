// Copyright (C) 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createRoot } from "react-dom/client";
import SwaggerUI from "swagger-ui-react";
import "swagger-ui-react/swagger-ui.css";

type ApiConfig = {
  openapiUrl: string;
  callbackUrl: string;
};

interface IWindow {
  API_CONFIG?: ApiConfig;
}

const config = typeof window !== "undefined" && (window as IWindow).API_CONFIG;
if (!config) {
  throw new Error("API_CONFIG is not defined");
}

createRoot(document.getElementById("root") as HTMLElement).render(
  <SwaggerUI url={config.openapiUrl} oauth2RedirectUrl={config.callbackUrl} />,
);
