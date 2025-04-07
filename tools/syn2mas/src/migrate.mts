// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { readFile } from "node:fs/promises";

import id128 from "id128";
import log4js from "log4js";
import { parse } from "ts-command-line-args";
import yaml from "yaml";

import { connectToMASDatabase, connectToSynapseDatabase } from "./db.mjs";
import { masConfig as masConfigSchema } from "./schemas/mas.mjs";
import { synapseConfig as synapseConfigSchema } from "./schemas/synapse.mjs";
import type { MCompatAccessToken } from "./types/MCompatAccessToken.d.ts";
import type { MCompatRefreshToken } from "./types/MCompatRefreshToken.d.ts";
import type { MCompatSession } from "./types/MCompatSession.d.ts";
import type { MUpstreamOauthLink } from "./types/MUpstreamOauthLink.d.ts";
import type { MUpstreamOauthProvider } from "./types/MUpstreamOauthProvider.d.ts";
import type { MUser } from "./types/MUser.js";
import type { MUserEmail } from "./types/MUserEmail.d.ts";
import type { MUserPassword } from "./types/MUserPassword.d.ts";
import type { SAccessToken } from "./types/SAccessToken.d.ts";
import type { SRefreshToken } from "./types/SRefreshToken.d.ts";
import type { SUser } from "./types/SUser.d.ts";
import type { SUserExternalId } from "./types/SUserExternalId.d.ts";
import type { SUserThreePid } from "./types/SUserThreePid.d.ts";
import type { UUID } from "./types/index.d.ts";

const log = log4js.getLogger("migrate");

interface MigrationOptions {
  command: string;
  synapseConfigFile: string;
  masConfigFile: string;
  upstreamProviderMapping: string[];
  skipGuests?: boolean;
  dryRun?: boolean;
  help?: boolean;
}

// Parses a string that is either a UUID or a ULID
// Returns [uuid, ulid] in canonical format
const parseUuidOrUlid = (input: string): [string, string] => {
  let bytes: Uint8Array;
  if (id128.Ulid.isCanonical(input)) {
    bytes = id128.Ulid.fromCanonicalTrusted(input).bytes;
  } else if (id128.Uuid.isCanonical(input)) {
    bytes = id128.Uuid.fromCanonicalTrusted(input).bytes;
  } else {
    bytes = id128.Uuid.fromRaw(input).bytes;
  }

  return [
    id128.Uuid.construct(bytes).toCanonical(),
    id128.Ulid.construct(bytes).toCanonical(),
  ];
};

export async function migrate(): Promise<void> {
  const args = parse<MigrationOptions>(
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
      masConfigFile: { type: String, description: "Path to MAS config.yaml" },
      upstreamProviderMapping: {
        type: String,
        defaultValue: [],
        multiple: true,
        description:
          "Mapping of upstream provider IDs to MAS provider IDs. Format: <upstream_provider_id>:<mas_provider_id>",
      },
      skipGuests: {
        type: Boolean,
        optional: true,
        defaultValue: false,
        description: "Skip and print warnings for any guests users found in Synapse, instead of aborting"
      },
      dryRun: {
        type: Boolean,
        optional: true,
        defaultValue: false,
        description: "Dry run only, do not write to database",
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
    warnings.push(message);
  }

  let fatals = 0;
  function fatal(message: string): void {
    log.fatal(message);
    for (const w of warnings) log.warn(w);
    if (!args.dryRun) {
      process.exit(1);
    }
    fatals += 1;
  }

  function makeUuid<T>(time: Date): UUID<T> {
    return id128.Uuid.construct(
      id128.Ulid.generate({ time }).bytes,
    ).toCanonical();
  }

  // load synapse config
  const synapseConfig = synapseConfigSchema.parse(
    yaml.parse(await readFile(args.synapseConfigFile, "utf8")),
  );

  // connect to synapse database
  const synapse = await connectToSynapseDatabase(synapseConfig);

  // load MAS config
  const masConfig = masConfigSchema.parse(
    yaml.parse(await readFile(args.masConfigFile, "utf8")),
  );

  // connect to MAS database
  const mas = await connectToMASDatabase(masConfig);

  const upstreamProviders = new Map<string, MUpstreamOauthProvider>();

  for (const mapping of args.upstreamProviderMapping) {
    const [providerId, masProviderId] = mapping.split(":");
    if (!providerId || !masProviderId) {
      throw new Error(
        `Upstream provider mapping is not in correct format. It should be <upstream_provider_id>:<mas_provider_id>: ${mapping}`,
      );
    }

    if (
      !id128.Uuid.isRaw(masProviderId) &&
      !id128.Uuid.isCanonical(masProviderId) &&
      !id128.Ulid.isCanonical(masProviderId)
    ) {
      throw new Error(
        `Upstream provider mapping is not in correct format. It should be a UUID or a ULID: ${masProviderId}`,
      );
    }

    const [masProviderUuid, masProviderUlid] = parseUuidOrUlid(masProviderId);

    log.info(
      `Loading existing upstream provider ${masProviderUlid} from MAS database as ${providerId}`,
    );
    const existingProvider = await mas("upstream_oauth_providers")
      .select("*")
      .where({ upstream_oauth_provider_id: masProviderUuid })
      .first();
    if (!existingProvider) {
      throw new Error(
        `Could not find upstream provider ${masProviderUlid} in MAS database`,
      );
    }
    upstreamProviders.set(providerId, existingProvider);
  }

  function stringifyAndRedact(input: unknown): string {
    const x = JSON.stringify(input);

    return x.replace(
      /("(password_hash|hashed_password|access_token|token)":")[^"]*"/,
      '$1redacted"',
    );
  }

  type Execution = () => Promise<void>;

  const existingMasUsers = await mas
    .count({ count: "*" })
    .from("users")
    .first();

  if (Number.parseInt(`${existingMasUsers?.count ?? 0}`) > 0) {
    fatal(
      `Found ${existingMasUsers?.count} existing users in MAS. Refusing to continue. Please clean MAS and try again.`,
    );
  }

  async function migrateUser(user: SUser): Promise<void> {
    const localpart = user.name.split(":")[0].substring(1);
    log.info(`Processing user ${user.name} as ${localpart}`);

    let warningsForUser = 0;
    const executions: Execution[] = [];

    if (user.is_guest === 1) {
      if (args.skipGuests) {
        log.warn(`Skipping guest user ${user.name}`);
      } else {
        fatal(`Migration of guest users is not supported: ${user.name}`);
      }
    }

    // users => users
    const userCreatedAt = new Date(
      Number.parseInt(`${user.creation_ts}`) * 1000,
    );
    const masUser: MUser = {
      user_id: makeUuid(userCreatedAt),
      username: localpart,
      created_at: userCreatedAt,
      locked_at: user.deactivated === 1 ? userCreatedAt : null,
      can_request_admin: user.admin === 1,
    };
    executions.push(() => mas.insert(masUser).into("users"));
    log.debug(`${stringifyAndRedact(user)} => ${stringifyAndRedact(masUser)}`);
    // users.password_hash => user_passwords
    if (user.password_hash) {
      const masUserPassword: MUserPassword = {
        user_password_id: makeUuid(userCreatedAt),
        user_id: masUser.user_id,
        hashed_password: user.password_hash,
        created_at: masUser.created_at, // TODO: should we use now() instead of created_at?
        version: 1,
      };

      log.debug(
        `Password ${user.password_hash.slice(-4)} => ${stringifyAndRedact(
          masUserPassword,
        )}`,
      );
      executions.push(() => mas.insert(masUserPassword).into("user_passwords"));
    }

    // user_threepids => user_emails
    const synapseThreePids = await synapse
      .select("*")
      .from<SUserThreePid>("user_threepids")
      .where({ user_id: user.name });
    for (const threePid of synapseThreePids) {
      if (threePid.medium !== "email") {
        warningsForUser += 1;
        warn(
          `Skipping non-email 3pid ${threePid.medium} for user ${user.name}`,
        );
        continue;
      }
      const threePidCreatedAt = new Date(
        Number.parseInt(`${threePid.added_at}`),
      );
      const masUserEmail: MUserEmail = {
        user_email_id: makeUuid(threePidCreatedAt),
        user_id: masUser.user_id,
        email: threePid.address.toLowerCase(),
        created_at: threePidCreatedAt,
      };

      if (threePid.validated_at) {
        masUserEmail.confirmed_at = new Date(
          Number.parseInt(`${threePid.validated_at}`),
        );
      }

      log.debug(
        `${stringifyAndRedact(threePid)} => ${stringifyAndRedact(
          masUserEmail,
        )}`,
      );
      executions.push(() => mas.insert(masUserEmail).into("user_emails"));
    }

    // user_external_ids => upstream_oauth_links
    const synapseExternalIds = await synapse
      .select("*")
      .from<SUserExternalId>("user_external_ids")
      .where({ user_id: user.name });
    for (const externalId of synapseExternalIds) {
      try {
        const provider = upstreamProviders.get(externalId.auth_provider);
        if (!provider) {
          throw new Error(
            `Unknown upstream provider ${externalId.auth_provider}`,
          );
        }
        const masUpstreamOauthLink: MUpstreamOauthLink = {
          upstream_oauth_link_id: makeUuid(userCreatedAt),
          user_id: masUser.user_id,
          upstream_oauth_provider_id: provider.upstream_oauth_provider_id,
          subject: externalId.external_id,
          created_at: masUser.created_at,
        };

        log.debug(
          `${stringifyAndRedact(synapseExternalIds)} => ${stringifyAndRedact(
            masUpstreamOauthLink,
          )}`,
        );

        executions.push(() =>
          mas.insert(masUpstreamOauthLink).into("upstream_oauth_links"),
        );
      } catch (e) {
        fatal(
          `Failed to import external id ${externalId.external_id} with ${externalId.auth_provider} for user ${user.name}: ${e}`,
        );
      }
    }

    // We only import access tokens for active users
    if (user.deactivated === 1) {
      log.info(
        `Skipping access tokens import for deactivated user ${user.name}`,
      );
    } else {
      // access_tokens,refresh_tokens => compat_sessions,compat_access_tokens
      const synapseAccessTokens = await synapse
        .select("*")
        .from<SAccessToken>("access_tokens")
        .where({ user_id: user.name })
        // Skip tokens without devices.
        // These can be for example short-lived tokens created by puppeting a user over the Synapse admin API.
        .whereNotNull("device_id");
      for (const accessToken of synapseAccessTokens) {
        const tokenCreatedAt = accessToken.last_validated
          ? new Date(Number.parseInt(`${accessToken.last_validated}`))
          : masUser.created_at;
        const masCompatSession: MCompatSession = {
          compat_session_id: makeUuid(tokenCreatedAt),
          user_id: masUser.user_id,
          device_id: accessToken.device_id,
          created_at: tokenCreatedAt,
          is_synapse_admin: user.admin === 1,
        };
        log.debug(
          `${stringifyAndRedact(accessToken)} => ${stringifyAndRedact(
            masCompatSession,
          )}`,
        );
        executions.push(() =>
          mas.insert(masCompatSession).into("compat_sessions"),
        );

        const masCompatAccessToken: MCompatAccessToken = {
          compat_access_token_id: makeUuid(tokenCreatedAt),
          compat_session_id: masCompatSession.compat_session_id,
          access_token: accessToken.token,
          created_at: tokenCreatedAt,
        };
        log.debug(
          `Access token ${accessToken.id} => ${stringifyAndRedact(
            masCompatAccessToken,
          )}`,
        );
        executions.push(() =>
          mas.insert(masCompatAccessToken).into("compat_access_tokens"),
        );

        if (accessToken.refresh_token_id) {
          const synapseRefreshToken = await synapse
            .select("*")
            .from<SRefreshToken>("refresh_tokens")
            .where({ id: accessToken.refresh_token_id })
            .first();
          if (synapseRefreshToken) {
            const masCompatRefreshToken: MCompatRefreshToken = {
              compat_refresh_token_id: makeUuid(tokenCreatedAt),
              compat_session_id: masCompatSession.compat_session_id,
              compat_access_token_id:
                masCompatAccessToken.compat_access_token_id,
              refresh_token: synapseRefreshToken.token,
              created_at: tokenCreatedAt,
            };
            log.debug(
              `Refresh token ${synapseRefreshToken.id} => ${stringifyAndRedact(
                masCompatRefreshToken,
              )}`,
            );
            executions.push(() =>
              mas.insert(masCompatRefreshToken).into("compat_refresh_tokens"),
            );
          } else {
            warningsForUser += 1;
            warn(
              `Unable to locate refresh token ${accessToken.refresh_token_id} for user ${user.name}`,
            );
          }
        }
      }
    }

    if (warningsForUser > 0) {
      if (!args.dryRun) {
        fatal(`User ${user.name} had ${warningsForUser} warnings`);
      } else {
        log.warn(`User ${user.name} had ${warningsForUser} warnings`);
      }
    } else if (!args.dryRun) {
      log.info(`Running ${executions.length} updates for user ${user.name}`);
      const tx = await mas.transaction();
      try {
        for (const execution of executions) {
          await execution();
        }
        await tx.commit();
        log.info(`Migrated user ${user.name}`);
      } catch (e) {
        try {
          await tx.rollback();
        } catch (e2) {
          log.error(`Failed to rollback transaction: ${e2}`);
        }
        throw e;
      }
    }
  }

  // this is a workaround to get the list of columns that we care about from the SUser type
  const SUserColumns: Record<keyof SUser, undefined> = {
    name: undefined,
    password_hash: undefined,
    admin: undefined,
    is_guest: undefined,
    deactivated: undefined,
    creation_ts: undefined,
    appservice_id: undefined,
  };

  // Get all Synapse users, except appservice owned users who don't need to be migrated
  const synapseUserQuery = synapse
    .select(Object.keys(SUserColumns) as (keyof SUser)[])
    .from<SUser>("users")
    .whereNull("appservice_id");

  let synapseUsers = 0;
  if (synapseConfig.database.name === "sqlite3") {
    // SQLite doesn't support streaming
    const synapseUserRows = (await synapseUserQuery) as unknown as SUser[];
    for (const user of synapseUserRows) {
      synapseUsers += 1;
      await migrateUser(user);
    }
  } else {
    // Stream users from the database
    const synapseUserStream = synapseUserQuery.stream();
    for await (const user of synapseUserStream) {
      synapseUsers += 1;
      await migrateUser(user as unknown as SUser);
    }
  }

  log.info(
    `Completed migration ${args.dryRun ? "dry-run " : ""}of ${synapseUsers} users with ${fatals} fatals and ${warnings.length} warnings:`,
  );
  for (const w of warnings) log.warn(w);
  if (fatals > 0) {
    throw new Error(`Migration failed with ${fatals} fatals`);
  }
}
