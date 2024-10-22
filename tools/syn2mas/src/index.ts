#!/usr/bin/env node
// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import log4js from "log4js";
import { type ArgumentConfig, parse } from "ts-command-line-args";

import { advisor } from "./advisor.mjs";
import { migrate } from "./migrate.mjs";

log4js.configure({
  appenders: {
    console: { type: "console" },
  },
  categories: {
    default: { appenders: ["console"], level: "debug" },
  },
});

const log = log4js.getLogger();

interface MainOptions {
  command: string;
  help?: boolean;
}

const mainArgOptions: ArgumentConfig<MainOptions> = {
  command: {
    type: String,
    description: "Command to run",
    defaultOption: true,
    typeLabel: "<advisor|migrate>",
  },
  help: {
    type: Boolean,
    optional: true,
    alias: "h",
    description: "Prints this usage guide",
  },
};

export const mainArgs = parse<MainOptions>(mainArgOptions, {
  stopAtFirstUnknown: true,
});

try {
  if (mainArgs.command === "migrate") {
    await migrate();
    process.exit(0);
  }

  if (mainArgs.command === "advisor") {
    await advisor();
    process.exit(0);
  }

  parse<MainOptions>(mainArgOptions, { helpArg: "help" });
  process.exit(1);
} catch (e) {
  log.error(e);
  process.exit(1);
}
