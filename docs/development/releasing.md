# Releasing

MAS follows the same release cadence as Synapse, meaning usually one full release cycle every two weeks, with one week of release candidates.

## GitHub Action workflows

There are four main GitHub Action workflows involved in releasing MAS:

### [`translations-download` workflow]

This workflow downloads the latest translations from [Localazy] onto the target branch.
It is intended to be run before the start of each release cycle on the main branch and before each release on the release branch.

Before running it, make sure to review pending translations in [Localazy], enabling new languages that pass the 70% threshold.

### [`release-branch` workflow]

This workflow starts a new major/minor release branch and bumps the version to the next major/minor pre-version.
It will tag the version, triggering the `build` workflow for it.

The next major/minor pre-version is computed from the current version on the main branch, so it works as follows:

 - `v1.2.3` will become `v2.0.0-rc.0` for a major release
 - `v1.2.3` will become `v1.3.0-rc.0` for a minor release

The release branch will be called `release/vX.Y`, and a PR will be automatically opened to merge it into the main branch.


### [`release-bump` workflow]

This workflow bumps the version on a release branch to either the next stable version or the next release candidate version.
This *cannot* be run on the main branch (and will fail if you try).

This workflow has three meaningful inputs:

 - The release branch to bump
 - Whether the release is a pre-release or not:
   - If it is a pre-release, `v1.2.3-rc.0` will become `v1.2.3-rc.1`, and `v1.2.3` will become `v1.2.4-rc.0`.
   - If it is not a pre-release, `v1.2.3-rc.0` will become `v1.2.3`, and `v1.2.3` will become `v1.2.4`.
 - Whether the release branch should be merged back into the main branch or not. In most cases, this should be enabled unless doing a release on a previous release branch.

### [`build` workflow]

This workflow is automatically run in three conditions:

 - When a `v*` tag is pushed
 - On the `main` branch
 - When a PR is tagged with the `Z-Build-Workflow` label (**note that this doesn't work on PRs from forks**)

In all cases, it will build and push a container image to ghcr.io and build binaries to GitHub Action assets.

For `v*` tags:

 - It will push the container image with the `MAJOR`, `MAJOR.MINOR`, `MAJOR.MINOR.PATCH`, `sha-HASH`, and `latest` tags for stable releases.
 - It will push the container image with the `MAJOR.MINOR.PATCH-rc.N` and `sha-HASH` tags for pre-releases.
 - It will **draft** a release on GitHub, with generated changelogs, reference to the built container image, and pre-built binaries attached to the release.

On the main branch:

 - It will push the container image with the `sha-HASH` and `main` tags.
 - It will update the [`unstable`](https://github.com/element-hq/matrix-authentication-service/releases/tag/unstable) GitHub release with the built container image and pre-built binaries.

When a PR is tagged with the `Z-Build-Workflow` label:

 - It will push the container image with the `sha-HASH` and `pr-NUMBER` tags.
 - It will comment on the PR with the built container image.
 - Pre-built binaries are available in the workflow artifacts.


## Changelog generation

Changelogs are automatically generated from PR titles and labels.

The configuration for those can be found in the `.github/release.yml`, but the main labels to be aware of are:

 - `T-Defect`: Bug fixes
 - `T-Enhancement`: New features
 - `A-Admin-API`: Changes to the admin API
 - `A-Documentation`: Documentation
 - `A-I18n`: Translations
 - `T-Task`: Internal changes
 - `A-Dependencies`: Dependency updates

They are calculated based on the previous release. For release candidates, this includes the previous release candidate.

## Undrafting releases

Releases are manually undrafted when the release is ready to be published.
At this point, the releaser should check the changelog and ensure the "Set as pre-release" and "Set as latest release" checkboxes are checked as appropriate.

## Full release process

 - Start a new release cycle:
   1. Run the [`translations-download` workflow] on the main branch.
   1. Wait for the [translation download PR] to be automatically merged.
   1. Run the [`release-branch` workflow] on the main branch.
   1. Wait for [CI to churn] and the [draft release to appear]. This takes about 30 minutes.
   1. Double-check the changelog on the draft release.
   1. Check the "Set as pre-release" checkbox, and publish the release.
   1. Delete the N-2 release branch on [Localazy], meaning that once the 0.16 release cycle begins, the 0.14 release branch will be deleted.
 - Create new release candidates if needed:
   1. Run the `translations-download` workflow on the release branch.
   1. Wait for the [translation download PR] to be automatically merged.
   1. Run the [`release-bump` workflow] on the release branch, with the `rc` input **checked**.
   1. Wait for [CI to churn] and the [draft release to appear]. This takes about 30 minutes.
   1. Double-check the changelog on the draft release.
   1. Check the "Set as pre-release" checkbox and publish the release.
 - Create a new stable release:
   1. Run the [`translations-download` workflow] on the release branch
   1. Wait for the [translation download PR] to be automatically merged
   1. Run the [`release-bump` workflow] on the release branch, with the `rc` input **unchecked**.
   1. Wait for [CI to churn] and the [draft release to appear]. This takes about 30 minutes.
   1. Double-check the changelog on the draft release.
   1. Check the "Set as latest release" checkbox and publish the release.

[Localazy]: https://localazy.com/p/matrix-authentication-service
[`translations-download` workflow]: https://github.com/element-hq/matrix-authentication-service/actions/workflows/translations-download.yaml
[`release-branch` workflow]: https://github.com/element-hq/matrix-authentication-service/actions/workflows/release-branch.yaml
[`release-bump` workflow]: https://github.com/element-hq/matrix-authentication-service/actions/workflows/release-bump.yaml
[`build` workflow]: https://github.com/element-hq/matrix-authentication-service/actions/workflows/build.yaml
[translation download PR]: https://github.com/element-hq/matrix-authentication-service/pulls?q=is%3Apr+label%3AA-I18n
[CI to churn]: https://github.com/element-hq/matrix-authentication-service/actions/workflows/build.yaml?query=event%3Apush+actor%3Amatrixbot
[draft release to appear]: https://github.com/element-hq/matrix-authentication-service/releases
