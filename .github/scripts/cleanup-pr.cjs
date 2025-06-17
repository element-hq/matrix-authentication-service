// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @ts-check

/** @param {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
module.exports = async ({ github, context }) => {
  const metadataJson = process.env.BUILD_IMAGE_MANIFEST;
  if (!metadataJson) throw new Error("BUILD_IMAGE_MANIFEST is not defined");
  /** @type {Record<string, {tags: string[]}>} */
  const metadata = JSON.parse(metadataJson);

  await github.rest.issues.removeLabel({
    issue_number: context.issue.number,
    owner: context.repo.owner,
    repo: context.repo.repo,
    name: "Z-Build-Workflow",
  });

  const tagListMarkdown = metadata.regular.tags
    .map((tag) => `- \`${tag}\``)
    .join("\n");

  // Get the workflow run
  const run = await github.rest.actions.getWorkflowRun({
    owner: context.repo.owner,
    repo: context.repo.repo,
    run_id: context.runId,
  });

  await github.rest.issues.createComment({
    issue_number: context.issue.number,
    owner: context.repo.owner,
    repo: context.repo.repo,
    body: `A build for this PR at commit <kbd>${context.sha}</kbd> has been created through the <kbd>Z-Build-Workflow</kbd> label by <kbd>${context.actor}</kbd>.

Docker image is available at:
${tagListMarkdown}

Pre-built binaries are available through the [workflow run artifacts](${run.data.html_url}).`,
  });
};
