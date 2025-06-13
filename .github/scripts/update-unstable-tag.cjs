// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @ts-check

/** @param {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
module.exports = async ({ github, context }) => {
  const { owner, repo } = context.repo;
  const sha = context.sha;

  const tag = await github.rest.git.updateRef({
    owner,
    repo,
    force: true,
    ref: "tags/unstable",
    sha,
  });
  console.log("Updated tag ref:", tag.data.url);
};
