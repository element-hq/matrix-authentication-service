// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @ts-check

/** @param {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
module.exports = async ({ github, context }) => {
  const { owner, repo } = context.repo;
  const sha = process.env.SHA;
  const branch = `ref-merge/${sha}`;
  if (!sha) throw new Error("SHA is not defined");

  await github.rest.git.createRef({
    owner,
    repo,
    ref: `refs/heads/${branch}`,
    sha,
  });
  console.log(`Created branch ${branch} to ${sha}`);

  // Create a PR to merge the branch back to main
  const pr = await github.rest.pulls.create({
    owner,
    repo,
    head: branch,
    base: "main",
    title: "Automatic merge back to main",
    body: "This pull request was automatically created by the release workflow. It merges the release branch back to main.",
    maintainer_can_modify: true,
  });
  console.log(
    `Created pull request #${pr.data.number} to merge the release branch back to main`,
  );
  console.log(`PR URL: ${pr.data.html_url}`);

  // Add the `T-Task` label to the PR
  await github.rest.issues.addLabels({
    owner,
    repo,
    issue_number: pr.data.number,
    labels: ["T-Task"],
  });

  // Enable auto-merge on the PR
  await github.graphql(
    `
      mutation AutoMerge($id: ID!) {
        enablePullRequestAutoMerge(input: {
          pullRequestId: $id,
          mergeMethod: MERGE,
        }) {
          clientMutationId
        }
      }
    `,
    { id: pr.data.node_id },
  );
};
