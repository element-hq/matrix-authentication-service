// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

type AppConfig = {
  root: string;
  graphqlEndpoint: string;
};

interface IWindow {
  APP_CONFIG?: AppConfig;
  RENDER_DATA?: any;
}

const config: AppConfig = (typeof window !== "undefined" &&
  (window as IWindow).APP_CONFIG) || {
  root: "/",
  graphqlEndpoint: "/graphql",
};

export default config;
