// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @ts-check

/** @param {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
module.exports = async ({ github, context }) => {
  const { owner, repo } = context.repo;
  const version = process.env.VERSION;
  const tagSha = process.env.TAG_SHA;

  if (!version) throw new Error("VERSION is not defined");
  if (!tagSha) throw new Error("TAG_SHA is not defined");

  const tag = await github.rest.git.createRef({
    owner,
    repo,
    ref: `refs/tags/v${version}`,
    sha: tagSha,
  });
  console.log("Created tag ref:", tag.data.url);
};
