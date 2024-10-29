// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { readFile } from "node:fs/promises";

import type { Knex } from "knex";
import log4js from "log4js";
import { parse } from "ts-command-line-args";
import yaml from "yaml";

import { connectToSynapseDatabase } from "./db.mjs";
import {
  type SynapseOIDCProvider,
  synapseConfig as synapseConfigSchema,
} from "./schemas/synapse.mjs";
import type { SAccessToken } from "./types/SAccessToken.d.ts";
import type { SRefreshToken } from "./types/SRefreshToken.d.ts";
import type { SUser } from "./types/SUser.d.ts";
import type { SUserThreePid } from "./types/SUserThreePid.d.ts";

const log = log4js.getLogger("migrate");

interface Options {
  command: string;
  synapseConfigFile: string;
  help?: boolean;
}

export async function advisor(): Promise<void> {
  const args = parse<Options>(
    {
      command: {
        type: String,
        description: "Command to run",
        defaultOption: true,
        typeLabel: "migrate",
      },
      synapseConfigFile: {
        type: String,
        description: "Path to synapse homeserver.yaml config file",
      },
      help: {
        type: Boolean,
        optional: true,
        alias: "h",
        description: "Prints this usage guide",
      },
    },
    {
      helpArg: "help",
    },
  );

  const warnings: string[] = [];
  function warn(message: string): void {
    log.warn(message);
    warnings.push(message);
  }

  const errors: string[] = [];
  function error(message: string): void {
    log.error(message);
    errors.push(message);
  }

  // load synapse config
  const synapseConfig = synapseConfigSchema.parse(
    yaml.parse(await readFile(args.synapseConfigFile, "utf8")),
  );

  // connect to synapse databases
  const synapse = await connectToSynapseDatabase(synapseConfig);

  async function count(query: Knex.QueryBuilder): Promise<number> {
    const res = await query.first();
    if (!res) {
      return 0;
    }
    return res["count(*)"] as number;
  }

  const guestUsers = await count(
    synapse.count("*").from<SUser>("users").where({ is_guest: 1 }),
  );
  if (guestUsers > 0) {
    error(
      `Synapse database contains ${guestUsers} guest users which aren't supported by MAS: https://github.com/element-hq/matrix-authentication-service/issues/1445`,
    );
  }
  if (synapseConfig.allow_guest_access) {
    if (guestUsers > 0) {
      error(
        "Synapse config allows guest access which isn't supported by MAS: https://github.com/element-hq/matrix-authentication-service/issues/1445",
      );
    } else {
      error(
        "Synapse config allows guest access which isn't supported by MAS, but no guest users were found in the database so the option could be disabled: https://github.com/element-hq/matrix-authentication-service/issues/1445",
      );
    }
  }

  if (synapseConfig.enable_registration) {
    warn(
      "Synapse config has registration enabled which will need to be disabled after migration",
    );
  }
  if (synapseConfig.enable_registration_captcha) {
    warn(
      "Synapse config has registration CAPTCHA enabled which will need to configured in MAS",
    );
  }
  if (synapseConfig.user_consent) {
    warn(
      "Synapse config has user_consent configured which will need to be disabled after migration",
    );
  }

  const usersWithoutEmailAddress = await count(
    synapse
      .count("*")
      .from<SUser>("users")
      .leftOuterJoin<SUserThreePid>(
        "user_threepids",
        "users.name",
        "user_threepids.user_id",
      )
      .whereNull("user_threepids.user_id"),
  );
  if (usersWithoutEmailAddress > 0) {
    warn(
      `Synapse database contains ${usersWithoutEmailAddress} users without a verified email address who will need to verify their email address before they can login after migration: https://github.com/element-hq/matrix-authentication-service/issues/1505`,
    );
  }

  const accessTokensWithoutDeviceId = await count(
    synapse
      .count("*")
      .from<SAccessToken>("access_tokens")
      .where({ device_id: "" })
      .orWhereNull("device_id"),
  );
  if (accessTokensWithoutDeviceId > 0) {
    error(
      `Synapse database contains ${accessTokensWithoutDeviceId} access tokens without an associated device_id which will be skipped during migration`,
    );
  }

  const nonEmailThreePids = await count(
    synapse
      .count("*")
      .from<SUserThreePid>("user_threepids")
      .whereNot({ medium: "email" }),
  );
  if (nonEmailThreePids > 0) {
    error(
      `Synapse database contains ${nonEmailThreePids} non-email 3pids which will be ignored during migration`,
    );
  }

  const oidcProviders: SynapseOIDCProvider[] = [
    ...(synapseConfig.oidc_providers ?? []),
    ...(synapseConfig.oidc_config ? [synapseConfig.oidc_config] : []),
  ];
  for (const provider of oidcProviders) {
    warn(
      `Synapse config contains OIDC auth configuration which will need mapping to be manually mapped to an upstream OpenID Provider during migration: ${provider.issuer}`,
    );
  }

  if (synapseConfig.cas_config?.enabled) {
    warn(
      "Synapse config contains CAS auth configuration which will need mapping to be manually mapped to an upstream OpenID Provider during migration",
    );
  }
  if (synapseConfig.saml2_config?.sp_config) {
    warn(
      "Synapse config contains SAML2 auth configuration which will need mapping to be manually mapped to an upstream OpenID Provider during migration",
    );
  }
  if (synapseConfig.jwt_config?.enabled) {
    warn(
      "Synapse config contains JWT auth configuration which will need mapping to be manually mapped to an upstream OpenID Provider during migration",
    );
  }
  if (
    synapseConfig.password_config?.enabled !== false &&
    synapseConfig.password_config?.localdb_enabled === false
  ) {
    warn(
      "Synapse has a non-standard password auth enabled which won't work after migration and will need to be manually mapped to an upstream OpenID Provider during migration",
    );
  } else if (synapseConfig.password_config?.enabled !== false) {
    warn(
      "Synapse has password auth enabled, but support for password auth in MAS is not feature complete",
    );
  }

  const externalIdAuthProviders = (await synapse
    .select("auth_provider")
    .count("* as Count")
    .from("user_external_ids")
    .groupBy("auth_provider")) as { auth_provider: string; Count: number }[];
  for (const row of externalIdAuthProviders) {
    warn(
      `An upstream OpenID Provider will need to be configured for the ${row.Count} users with auth provider ${row.auth_provider}`,
    );
  }

  const usersWithPassword = await count(
    synapse.count("*").from<SUser>("users").whereNotNull("password_hash"),
  );
  if (usersWithPassword > 0) {
    warn(
      `Synapse database contains ${usersWithPassword} users with a password which will be migrated. However, support for password auth in MAS is not feature complete`,
    );
  }

  const accessTokensToImport = await count(
    synapse
      .count("*")
      .from<SAccessToken>("access_tokens")
      .whereNotNull("device_id"),
  );
  if (accessTokensToImport > 0) {
    log.info(
      `Synapse database contains ${accessTokensToImport} access tokens which will be migrated`,
    );
  }

  const synapseRefreshToken = await count(
    synapse.select("*").from<SRefreshToken>("refresh_tokens"),
  );
  if (synapseRefreshToken > 0) {
    log.info(
      `Synapse database contains ${synapseRefreshToken} refresh tokens which will be migrated`,
    );
  }

  if (synapseConfig.enable_3pid_changes === true) {
    warn(
      "Synapse config has enable_3pid_changes enabled which must to be disabled or removed after migration",
    );
  }

  if (synapseConfig.login_via_existing_session?.enabled === true) {
    warn(
      "Synapse config has login_via_existing_session enabled which must to be disabled or removed after migration",
    );
  }

  process.exit(errors.length > 0 ? 1 : 0);
}
