// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

export type AppConfig = {
  root: string;
  graphqlEndpoint: string;
};

interface IWindow {
  APP_CONFIG?: AppConfig;
}

const config: AppConfig = (typeof window !== "undefined" &&
  (window as IWindow).APP_CONFIG) || {
  root: "/",
  graphqlEndpoint: "/graphql",
};

export default config;
