# CI, branch protection and the release process

This describes the system that exists. If something here disagrees with the workflow
files, the workflow files are right and this document is a bug: please report it.

It exists because the answers used to be recoverable only by reading five YAML files
and inferring the rules between them. A contributor should be able to find out what
runs, what blocks a merge, what has to be green, and how a release is cut, without
reverse-engineering any of that.

## What runs when

| pull request event | CI (`ci.yml`) | PR Metadata Policy | AAHP Verify |
| --- | --- | --- | --- |
| `opened` | yes | yes | yes |
| `reopened` | yes | yes | yes |
| `synchronize` (a new commit) | yes | yes | yes |
| `ready_for_review` | no | no | no |
| `edited` (title or body) | **no** | **yes** | no |

Three things in that table look wrong at a glance and are deliberate. Each one was
a real defect at some point, so none of them should be "tidied up".

**`edited` does not reach CI.** Editing a PR title or body cannot change the code, so
running the full build, test, package and security pipeline against an unchanged head
commit is pure waste. It used to happen, because the attribution gate needed to re-run
on a body edit, and the side effect was two or three CI runs on a single commit. The
title and body half of that gate now lives in its own workflow.

**`ready_for_review` reaches nothing.** It creates no new head commit, and no job is draft-gated, so a draft pull request's `opened` and `synchronize` runs have already made that commit conclusive. Including it would start a duplicate full matrix on an identical tree and, because obsolete runs are cancelled, could replace a green result with a cancelled one.

**`synchronize` does reach the metadata workflow**, which looks redundant and is not.
A required status check is evaluated against the check runs attached to the **head
commit**. A workflow that never runs on `synchronize` leaves every pushed-to pull
request with a head commit carrying no run of it at all, and the required check then
blocks forever on a result that never arrives. The job is a few seconds with no
checkout, which is what makes running it on every push affordable.

## The three required checks

Merging into `main` requires these, and admins are not exempt.

| check name | produced by | what it means |
| --- | --- | --- |
| `Build and Test` | `ci.yml`, job `build` | every Node lane passed and the container image builds and scans |
| `aahp-verify` | `aahp-verify.yml` | the handoff state is intact and moved with the code |
| `PR metadata policy` | `pr-metadata-policy.yml` | the PR title and body carry no tool or model attribution |

**Exactly one workflow produces each name.** If two workflows reported under one name,
branch protection would see two runs competing to define a single context, and which
one won would depend on timing.

`Build and Test` is an aggregator. The real work runs in `compat (Node 20)`,
`compat (Node 22)` and `Docker build and smoke`; the aggregator is a single step that
fails unless all of them succeeded. It works that way because the check **name** is a
contract with branch protection: turning the job itself into a matrix would rename it
to `Build and Test (20)` and `Build and Test (22)` and delete the context that
protection waits for.

The aggregator runs with `if: always()`. Without that it would be **skipped** when a
dependency fails, and a skipped required check is not a failing one, so a red matrix
could report as a non-failure.

## Adding or renaming a required check

The order matters and getting it backwards blocks the repository.

1. Merge the workflow to `main` first.
2. Only then add the check name to the branch protection contexts.

Requiring a name whose workflow is not yet on `main` means every pull request waits on
a check that can never run. For the same reason, never rename a job that produces a
required context without updating protection in the same operation.

Branch protection is edited from a maintainer workstation, not from a workflow. No
write-capable credential is added to any workflow, and nothing that can execute pull
request code has permission to change protection.

## Every workflow

| file | trigger | responsibility |
| --- | --- | --- |
| `ci.yml` | PR, push to `main`, semver tags | build, gates, full suite on every Node lane, container smoke, and on a tag: npm publish, GitHub Release, `v5` branch fast-forward |
| `pr-metadata-policy.yml` | PR open/edit/reopen/sync | PR title and body attribution policy. No checkout, so it cannot execute PR code |
| `aahp-verify.yml` | PR, push to `main` | the four-layer AAHP handoff gate, with no escape hatch at CI level |
| `docker.yml` | semver tags | builds the image multi-arch on native runners and pushes it to ghcr |
| `demo.yml` | manual only | renders `demo.gif` |

Note the split in the container path. `docker.yml` publishes, and it runs only on a
tag. `ci.yml`'s `Docker build and smoke` job validates, and it runs on every pull
request: it builds both stages, asserts the image runs the Node major the policy
declares, checks the packaged CLI reports the expected version, and runs a real scan
from inside the image. It never pushes. Before it existed, the first build of any
Dockerfile or base image change happened during the release itself.

## Validation gates

`npm run build` is not just `tsc`. Its `prebuild` runs three groups, and a red gate is
the task, not an obstacle to route around:

```
npm run check:aahp     # pin preflight, then: npx --no-install aahp check .
npm run check:feed     # node scripts/generate-feed.mjs --check
npm run check:handoff  # node scripts/scg-handoff-docs.mjs --check
```

`check:aahp` first runs `scripts/check-aahp-pin.mjs`, which asserts the governance
CLI that is about to speak is the exact version `package.json` pins. That preflight
exists because `npx --no-install` suppresses a download but still resolves a
**globally installed** `aahp` on PATH, so a checkout with a missing `node_modules`
silently ran a different version and printed `Governance OK`. A gate that fails open
is worse than no gate, because it manufactures the evidence of its own success.

It then runs seven config-driven gates, all declared in `aahp.config.json`:

| gate | fails when |
| --- | --- |
| `changelog` | `CHANGELOG.md` has no entry for the current version |
| `changelog-format` | Keep a Changelog grammar or SemVer ordering is broken |
| `version-sync` | the version in `package.json` is missing from any configured version site |
| `claims` | the capability numbers disagree across the surfaces that quote them |
| `forbidden-patterns` | published files carry AI attribution, or another banned pattern |
| `schema-doc-sync` | documented schema and code disagree, including the `[Unreleased]` compare link |
| `doc-links` | an internal documentation link does not resolve |

Two of these bite on a version bump specifically. `feed.json` embeds the version, so
`check:feed` goes red on **every** bump and not only when threat intelligence changed:
fix it with `npm run feed:generate`. And `check:handoff` goes red whenever the tracked
file inventory changes, including a dependency bump: fix it with
`npm run handoff:refresh`.

There are also two contract tests that are ordinary suite members but worth knowing
about, because they fail on configuration rather than on code:

- `src/__tests__/node-version-contract.test.ts` holds every Node declaration in the
  repository to `docs/node-support.md`.
- `src/__tests__/workflow-trigger-contract.test.ts` holds the workflows to the
  event-to-workflow matrix at the top of this file.

And one script that validates the artifact rather than the working tree:
`scripts/validate-package.sh` packs the tarball, checks its contents against the
manifest, installs it into a directory that shares nothing with the checkout, and
drives the CLI and the programmatic entry point from that install. It runs inside each
Node lane in CI, and you can run it locally with `bash scripts/validate-package.sh`.

## Running things locally

Run the **targeted** suite for what you changed:

```
npx vitest run src/__tests__/<the-file-you-touched>.test.ts
```

Do not run the full suite on Windows. It takes hours there, and a handful of VS Code
extension scanner tests fail for a missing `zip` binary regardless of your change.
Push and let Linux CI produce the full-suite verdict, or run it on a Linux machine. If
a suite looks broken, run it on an unmodified `main` first: several tests fail on
Windows on `main` itself, and that is the environment, not a regression.

## Node versions

`docs/node-support.md` is the authoritative policy: which majors are supported, which
are in transition and until when, what the artifact is published from, and what the
Action and container image run on. It is a machine-readable block that a gate holds
every declaration site to, so it cannot quietly go stale.

The short version as of v5.28.0: **Node 22 is the baseline**. Node 20 is a transition
lane, still fully tested but out of support, and it is removed in 5.29.0. That
milestone is enforced by the gate rather than remembered.

## Releasing

`main` is protected and cannot be pushed to directly, so a release is a pull request
like any other. In order:

1. **`CHANGELOG.md`**: add a `## [X.Y.Z] - YYYY-MM-DD` block below `## [Unreleased]`,
   with Keep a Changelog subsections, plus a reference link at the file foot. Update
   the `[Unreleased]` compare link to the new tag, which `schema-doc-sync` checks.
2. **`SECURITY.md`**: only for a new major or minor, and only if the supported range
   actually changes. The table is keyed by major.
3. **`CONTRIBUTING.md`**: only when new modules or files were added.
4. **Bump the version at every site.** Read the list from the config rather than from
   any prose, because it changes:
   `node -e "require('./aahp.config.json').versionSites.forEach(s=>console.log(s.minOccurrences,s.file))"`.
   Bump `package.json` too, then run `npm install --package-lock-only`: npm rewrites
   the lockfile's version fields only at install time, so an edit-based bump leaves it
   a release behind.
5. **`npm run feed:generate`**, since `feed.json` carries the version.
6. **`npm run build`** and **`npm test`** must be green.
7. One commit for everything: code, docs and tests together.
8. Open a pull request and squash-merge it once the required checks pass.
9. Tag the **merged** commit on `main`, never the pre-merge commit, and push the tag.
   Pushing the tag is what triggers publish, the GitHub Release, the `v5` fast-forward
   and the multi-arch image build.
10. Delete the branch and confirm it is gone on **both** sides. When a release is
    finished the repository has exactly two branches, `main` and `v5`, no open pull
    requests and no open issues.

Two rules that have each cost a release:

- **Never move a tag.** A bad release means a new patch version, never `git tag -f`.
- **Check the branch you are cutting from.** Run `git rev-parse --abbrev-ref HEAD`
  before `git checkout -b`. A branch cut while the tree sat on someone else's topic
  branch carries that branch's entire content into the squash merge.

## Open transition exceptions

Tracked in `.ai/handoff/STATUS.md` and `.ai/handoff/NEXT_ACTIONS.md`, not in the issue
tracker: this repository deliberately holds zero open issues, so an issue is not a
durable place to record anything.
