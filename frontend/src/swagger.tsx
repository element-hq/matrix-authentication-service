// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { SwaggerUIBundle, SwaggerUIStandalonePreset } from "swagger-ui-dist";
import "swagger-ui-dist/swagger-ui.css";

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

SwaggerUIBundle({
  url: "./spec.json",
  dom_id: "#swagger-ui",
  deepLinking: true,
  presets: [SwaggerUIStandalonePreset],
});
