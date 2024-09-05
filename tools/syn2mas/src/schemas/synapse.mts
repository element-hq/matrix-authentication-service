// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import * as z from "zod";

const sqlite3DatabaseConfig = z.object({
  name: z.literal("sqlite3"),
  args: z.object({
    database: z.string(),
  }),
});

const psycopg2DatabaseConfig = z.object({
  name: z.literal("psycopg2"),
  args: z.object({
    user: z.string().nullish(),
    password: z.string().nullish(),
    database: z.string().nullish(),
    dbname: z.string().nullish(),
    host: z.string().nullish(),
    port: z.union([z.number(), z.string()]).nullish(),
    sslcert: z.string().nullish(),
    sslkey: z.string().nullish(),
    sslpassword: z.string().nullish(),
    sslrootcert: z.string().nullish(),
  }),
});

const databaseConfig = z.union([sqlite3DatabaseConfig, psycopg2DatabaseConfig]);

const oidcProviderConfig = z.object({
  idp_id: z.string(),
  idp_name: z.string().nullish(),
  issuer: z.string(),
  client_id: z.string(),
  scopes: z.array(z.string()),
  client_auth_method: z
    .union([
      z.literal("client_secret_basic"),
      z.literal("client_secret_post"),
      z.literal("none"),
    ])
    .nullish(),
  client_secret: z.string().nullish(),
  client_secret_jwt_key: z.string().nullish(),
});

export type SynapseOIDCProvider = z.infer<typeof oidcProviderConfig>;

export const synapseConfig = z.object({
  database: databaseConfig,
  oidc_providers: z.array(oidcProviderConfig).nullish(),
  oidc_config: oidcProviderConfig.nullish(),
  allow_guest_access: z.boolean().nullish(),
  cas_config: z
    .object({
      enabled: z.boolean().nullish(),
    })
    .nullish(),
  saml2_config: z
    .object({
      sp_config: z.object({}).nullish(),
    })
    .nullish(),
  sso: z
    .object({
      client_whitelist: z.array(z.string()).nullish(),
      update_profile_information: z.boolean().nullish(),
    })
    .nullish(),
  jwt_config: z
    .object({
      enabled: z.boolean().nullish(),
    })
    .nullish(),
  password_config: z
    .object({
      enabled: z.boolean().nullish(),
      localdb_enabled: z.boolean().nullish(),
    })
    .nullish(),
  enable_registration_captcha: z.boolean().nullish(),
  enable_registration: z.boolean().nullish(),
  user_consent: z.object({}).nullish(),
  enable_3pid_changes: z.boolean().nullish(),
  login_via_existing_session: z
    .object({
      enabled: z.boolean().nullish(),
    })
    .nullish(),
});

export type SynapseConfig = z.infer<typeof synapseConfig>;
