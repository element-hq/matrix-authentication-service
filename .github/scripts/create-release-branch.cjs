// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @ts-check

/** @param {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
module.exports = async ({ github, context }) => {
  const { owner, repo } = context.repo;
  const branch = process.env.BRANCH;
  const sha = process.env.SHA;
  if (!sha) throw new Error("SHA is not defined");

  await github.rest.git.createRef({
    owner,
    repo,
    ref: `refs/heads/${branch}`,
    sha,
  });
  console.log(`Created branch ${branch} from ${sha}`);
};
