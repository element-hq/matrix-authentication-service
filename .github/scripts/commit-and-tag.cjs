// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @ts-check

/** @param {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
module.exports = async ({ github, context }) => {
  const fs = require("node:fs/promises");
  const { owner, repo } = context.repo;
  const version = process.env.VERSION;
  const parent = context.sha;
  if (!version) throw new Error("VERSION is not defined");

  const files = ["Cargo.toml", "Cargo.lock"];

  /** @type {{path: string, mode: "100644", type: "blob", sha: string}[]} */
  const tree = [];
  for (const file of files) {
    const content = await fs.readFile(file);
    const blob = await github.rest.git.createBlob({
      owner,
      repo,
      content: content.toString("base64"),
      encoding: "base64",
    });
    console.log(`Created blob for ${file}:`, blob.data.url);

    tree.push({
      path: file,
      mode: "100644",
      type: "blob",
      sha: blob.data.sha,
    });
  }

  const treeObject = await github.rest.git.createTree({
    owner,
    repo,
    tree,
    base_tree: parent,
  });
  console.log("Created tree:", treeObject.data.url);

  const commit = await github.rest.git.createCommit({
    owner,
    repo,
    message: version,
    parents: [parent],
    tree: treeObject.data.sha,
  });
  console.log("Created commit:", commit.data.url);

  const tag = await github.rest.git.createTag({
    owner,
    repo,
    tag: `v${version}`,
    message: version,
    type: "commit",
    object: commit.data.sha,
  });
  console.log("Created tag:", tag.data.url);

  return { commit: commit.data.sha, tag: tag.data.sha };
};
