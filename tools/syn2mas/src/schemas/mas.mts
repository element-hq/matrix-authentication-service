// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import * as z from "zod";

const ssl = z
  .object({
    ssl_ca: z.string().optional(),
    ssl_ca_file: z.string().optional(),
    ssl_certificate: z.string().optional(),
    ssl_certificate_file: z.string().optional(),
    ssl_key: z.string().optional(),
    ssl_key_file: z.string().optional(),
  })
  .refine((ssl) => {
    if (ssl.ssl_ca && ssl.ssl_ca_file) {
      throw new Error("Cannot specify both ssl_ca and ssl_ca_file");
    }

    if (ssl.ssl_certificate && ssl.ssl_certificate_file) {
      throw new Error("Cannot specify both ssl_cert and ssl_cert_file");
    }

    if (ssl.ssl_key && ssl.ssl_key_file) {
      throw new Error("Cannot specify both ssl_key and ssl_key_file");
    }

    return true;
  });

const uriDatabaseConfig = z
  .object({
    uri: z.string(),
  })
  .and(ssl);

export type URIDatabaseConfig = z.infer<typeof uriDatabaseConfig>;

const objectDatabaseConfig = z
  .object({
    host: z.string().optional(),
    port: z.number().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    database: z.string().optional(),
  })
  .and(ssl);

const databaseConfig = z.union([uriDatabaseConfig, objectDatabaseConfig]);

export type DatabaseConfig = z.infer<typeof databaseConfig>;

const secretsConfig = z.object({
  encryption: z.string(),
});

export const masConfig = z.object({
  database: databaseConfig,
  secrets: secretsConfig,
});

export type MASConfig = z.infer<typeof masConfig>;
